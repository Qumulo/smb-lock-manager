from quart import Quart, render_template, request, Response, jsonify, g
from functools import wraps
import requests
import urllib3
import os
import configparser
import json
import redis
import asyncio
import aiohttp
import gzip
import base64

app = Quart(__name__)

# Load and apply the config file.
config = configparser.ConfigParser()
config_path = "/usr/app/async_main.conf" if os.path.exists("/usr/app/async_main.conf") else os.path.join(os.path.dirname(__file__), "async_main.conf")
config.read(config_path)

CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]
USE_SSL = config["CLUSTER"].getboolean('USE_SSL')  # False = ignore TLS errors (allow self-signed certs)
WEBUI_ADMIN_USERNAME = config["WEBUI_ADMIN"]["USERNAME"]
WEBUI_ADMIN_PASSWORD = config["WEBUI_ADMIN"]["PASSWORD"]
WEBUI_ADMIN_TOKEN = config["WEBUI_ADMIN"]["TOKEN"]
WEBUI_READONLY_USERNAME = config["WEBUI_READONLY"]["USERNAME"]
WEBUI_READONLY_PASSWORD = config["WEBUI_READONLY"]["PASSWORD"]
WEBUI_READONLY_TOKEN = config["WEBUI_READONLY"]["TOKEN"]

rw_required_rights = [
    'PRIVILEGE_FS_LOCK_READ',
    'PRIVILEGE_SMB_FILE_HANDLE_READ',
    'PRIVILEGE_SMB_FILE_HANDLE_WRITE',
    'PRIVILEGE_IDENTITY_READ'
]
ro_required_rights = [
    'PRIVILEGE_FS_LOCK_READ',
    'PRIVILEGE_SMB_FILE_HANDLE_READ',
    'PRIVILEGE_IDENTITY_READ'
]

# Redis configuration
redis_host = os.environ.get('REDIS_HOST') or ('redis' if os.path.exists('/.dockerenv') else 'localhost')
redis_port = 6379
redis_db = redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)

if not USE_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Helper to build URLs - always use HTTPS for Qumulo clusters
def build_url(path):
    return f"https://{CLUSTER_ADDRESS}{path}"


# Redis data compression helpers (70-80% memory savings)
def compress_json(data):
    """Compress JSON data for Redis storage - saves significant memory"""
    json_str = json.dumps(data)
    compressed = gzip.compress(json_str.encode('utf-8'))
    return base64.b64encode(compressed).decode('utf-8')


def decompress_json(compressed_data):
    """Decompress JSON data from Redis"""
    if not compressed_data:
        return None
    try:
        decoded = base64.b64decode(compressed_data.encode('utf-8'))
        decompressed = gzip.decompress(decoded)
        return json.loads(decompressed.decode('utf-8'))
    except:
        # Fallback for uncompressed data (backward compatibility)
        return json.loads(compressed_data)

# Basic Auth functions
def check_auth(username, password):
    if username == WEBUI_ADMIN_USERNAME and password == WEBUI_ADMIN_PASSWORD:
        return 'admin', WEBUI_ADMIN_TOKEN
    elif username == WEBUI_READONLY_USERNAME and password == WEBUI_READONLY_PASSWORD:
        return 'readonly', WEBUI_READONLY_TOKEN
    return None

def failed_authentication():
    return Response(
        '<h1>Could not verify your access level for this service.\nAccess denied</h1>',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        auth = request.authorization
        auth_result = check_auth(auth.username, auth.password) if auth else None
        if not auth_result:
            return failed_authentication()
        user_role, user_token = auth_result
        g.user_role = user_role
        g.token = user_token
        return await f(*args, **kwargs)
    return decorated

# Build headers on demand using g.token
def get_headers():
    return {
        "Authorization": f"Bearer {g.token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

# Lookup user name and rights from the cluster API.
def verify_id_and_rights():
    url = build_url("/api/v1/session/who-am-i")
    user_info = requests.get(url, headers=get_headers(), verify=False).json()
    who_am_i = user_info['name']
    user_rbac_privileges = user_info['privileges']
    rw_matching_rights = [x for x in rw_required_rights if x in user_rbac_privileges]
    ro_matching_rights = [x for x in ro_required_rights if x in user_rbac_privileges]

    if set(rw_matching_rights) == set(rw_required_rights):
        user_has_rights = True
        user_rw_rights = True
    elif set(ro_matching_rights) == set(ro_required_rights):
        user_has_rights = True
        user_rw_rights = False
    else:
        user_has_rights = False
        user_rw_rights = False

    return who_am_i, user_has_rights, user_rw_rights

# Logout function
@app.route('/logout')
async def logout():
    html = """
    <html>
      <head>
        <!-- Redirect to the home page ("/") after 2 seconds -->
        <meta http-equiv="refresh" content="2;url=/" />
      </head>
      <body>
        <h1>You have been logged out.</h1>
        <p>If you are not redirected automatically, <a href="/">click here</a>.</p>
      </body>
    </html>
    """
    # Return a 401 response to force the browser to clear its cached Basic Auth credentials.
    return Response(html, 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


# Load root page of web UI.
@app.route('/')
@requires_auth
async def index():
    who_am_i, user_allowed, user_rw_rights = verify_id_and_rights()
    if not user_allowed:
        return await render_template('access_denied.html')
    rw_user = True if g.user_role == 'admin' else False
    return await render_template('index.html', who_am_i=who_am_i, cluster_address=CLUSTER_ADDRESS, rw_user=rw_user)


# Web UI search function (optimized with batch owner resolution).
@app.route('/search_files', methods=['POST'])
@requires_auth
async def search_files():
    form_data = await request.get_json()
    query = form_data['query'].lower() if form_data else ""

    open_files_raw = redis_db.get('open_files')
    handle_owner_raw = redis_db.get('handle_owner')

    if open_files_raw and handle_owner_raw:
        open_files = decompress_json(open_files_raw)
        handle_owner = decompress_json(handle_owner_raw)
    else:
        open_files, handle_owner = await path_loader()

    smb_locks_raw = redis_db.get('smb_locks')
    smb_locks = decompress_json(smb_locks_raw) if smb_locks_raw else {}

    # Filter grants based on query
    if query:
        matching_file_ids = {file_id for file_id, file_path in open_files.items() if query in file_path.lower()}
        matching_grants = [g for g in smb_locks.get("grants", []) if g["file_id"] in matching_file_ids]
    else:
        matching_grants = smb_locks.get("grants", [])

    # Collect unique owner IDs from matching grants
    unique_owner_ids = {handle_owner.get(g["file_id"]) for g in matching_grants if handle_owner.get(g["file_id"])}

    # Batch resolve all owners in parallel (major performance improvement)
    owner_map = await batch_resolve_owners(unique_owner_ids)

    # Build results with resolved owners
    lock_data = []
    for grant in matching_grants:
        file_id = grant["file_id"]
        owner_id = handle_owner.get(file_id, "")
        lock_data.append({
            "file_id": file_id,
            "file_path": open_files.get(file_id, "Unknown"),
            "mode": ", ".join(grant.get("mode", [])),
            "user": owner_map.get(str(owner_id), "Unknown"),
            "owner_address": grant.get("owner_address", ""),
            "node_address": grant.get("node_address", "")
        })

    return jsonify(lock_data)

# Load all currently held SMB locks (async version with fixed pagination)
@app.route('/get_smb_locks', methods=['GET'])
@requires_auth
async def get_smb_locks():
    base_url = build_url("/api/v1/files/locks/smb/share-mode/")

    try:
        # Use async pagination with fixed loop termination
        smb_locks = await fetch_all_lock_pages(base_url)

        # Store in Redis with compression (70-80% memory savings)
        redis_db.set('smb_locks', compress_json(smb_locks), ex=3600)

        # Load file paths and owners concurrently
        open_files, handle_owner = await path_loader()

        locks_count = len(smb_locks.get('grants', []))
        return jsonify({
            "locks_count": locks_count,
            "message": "SMB locks and file mappings updated successfully"
        })
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 400


async def fetch_all_lock_pages(base_url):
    """Async pagination for SMB locks - non-blocking I/O"""
    all_grants = []
    async with aiohttp.ClientSession() as session:
        url = base_url
        while url:
            async with session.get(url, headers=get_headers(), ssl=USE_SSL) as response:
                if response.status == 200:
                    data = await response.json()
                    grants = data.get('grants', [])
                    # Stop pagination if no grants (prevents infinite loop)
                    if not grants:
                        break
                    all_grants.extend(grants)
                    next_page = data.get('paging', {}).get('next')
                    url = build_url(next_page) if next_page else None
                else:
                    break
    return {"grants": all_grants}

# Batch resolve multiple owners in parallel (major performance improvement).
async def batch_resolve_owners(owner_ids):
    """Resolve multiple owner IDs concurrently - much faster than sequential"""
    # Check cache first
    cached_owners_raw = redis_db.get("resolved_owner")
    cached_owners = json.loads(cached_owners_raw) if cached_owners_raw else {}

    owner_map = {}
    to_resolve = []

    # Separate cached vs uncached owners
    for owner_id in owner_ids:
        owner_str = str(owner_id)
        if owner_str in cached_owners:
            owner_map[owner_str] = cached_owners[owner_str]["name"]
        else:
            to_resolve.append(owner_str)

    # Resolve uncached owners in parallel (concurrent API requests)
    if to_resolve:
        url = build_url("/api/v1/identity/find")

        async with aiohttp.ClientSession() as session:
            tasks = []
            for owner_id in to_resolve:
                task = resolve_single_owner(session, url, owner_id, owner_map, cached_owners)
                tasks.append(task)

            # Execute all requests concurrently
            await asyncio.gather(*tasks, return_exceptions=True)

        # Update cache with newly resolved owners
        redis_db.set("resolved_owner", json.dumps(cached_owners), ex=3600)

    return owner_map


async def resolve_single_owner(session, url, owner_id, owner_map, cache):
    """Helper to resolve a single owner - called concurrently by batch_resolve_owners"""
    try:
        async with session.post(url, json={"auth_id": owner_id}, headers=get_headers(), ssl=False) as response:
            if response.status == 200:
                data = await response.json()
                name = data.get("name", "Unknown")
                owner_map[owner_id] = name
                cache[owner_id] = {"name": name}
            else:
                owner_map[owner_id] = "Unknown"
    except Exception:
        owner_map[owner_id] = "Unknown"


# Resolve owner identity (legacy - kept for compatibility).
@requires_auth
async def resolve_owner(owner: int):
    """Single owner resolution - use batch_resolve_owners for better performance"""
    cached_owners = redis_db.get("resolved_owner")
    resolved_owners = json.loads(cached_owners) if cached_owners else {}

    owner_str = str(owner)
    if owner_str in resolved_owners:
        return {"name": resolved_owners[owner_str]["name"]}

    url = build_url("/api/v1/identity/find")
    owner_json = {"auth_id": owner_str}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=owner_json, headers=get_headers(), ssl=False) as response:
            if response.status == 200:
                owner_name = await response.json()
                resolved_owners[owner_str] = owner_name
                redis_db.set("resolved_owner", json.dumps(resolved_owners), ex=3600)
                return {"name": owner_name.get("name")}
            else:
                return {"error": f"Failed to resolve owner: HTTP {response.status}"}

# Load all currently held SMB file handles (with O(1) indexing).
async def path_loader():
    base_url = build_url("/api/v1/smb/files/?resolve_paths=true")
    handles = await fetch_all_pages(base_url)

    file_number_to_path = {handle["file_number"]: handle["handle_info"]["path"] for handle in handles}
    file_number_to_owner = {handle["file_number"]: handle["handle_info"]["owner"] for handle in handles}

    # Store with compression for memory efficiency
    redis_db.set('open_files', compress_json(file_number_to_path))
    redis_db.set('handle_owner', compress_json(file_number_to_owner), ex=3600)

    # Store handles in Redis hash for O(1) lookup (instead of O(n) linear search)
    # This dramatically speeds up close_handles operation
    pipe = redis_db.pipeline()
    pipe.delete('handles_index')  # Clear old index
    for handle in handles:
        pipe.hset('handles_index', handle["file_number"], json.dumps(handle))
    pipe.expire('handles_index', 3600)
    pipe.execute()

    return file_number_to_path, file_number_to_owner

# API pagination helper for path_loader().
@requires_auth
async def fetch_all_pages(base_url):
    handles = []
    async with aiohttp.ClientSession() as session:
        url = base_url
        while url:
            async with session.get(url, headers=get_headers(), ssl=USE_SSL) as response:
                if response.status == 200:
                    data = await response.json()
                    file_handles = data.get('file_handles', [])
                    # Stop pagination if no handles (prevents infinite loop)
                    if not file_handles:
                        break
                    handles.extend(file_handles)
                    next_page = data.get('paging', {}).get('next')
                    url = build_url("/api" + next_page) if next_page else None
                else:
                    break
    return handles

# Helper function to find a handle (O(1) lookup with Redis hash).
def find_handle(file_id):
    """Instant handle lookup using Redis hash - O(1) instead of O(n)"""
    handle_json = redis_db.hget('handles_index', str(file_id))
    if handle_json:
        return json.loads(handle_json)
    return None

# Helper function to close a single handle - called concurrently by close_handles
async def close_single_handle(session, file_id, handle, results):
    """Close a single handle with proper error handling"""
    try:
        url = build_url("/api/v1/smb/files/close")
        async with session.post(url, headers=get_headers(), json=[handle], ssl=False) as response:
            if response.status == 200:
                results['successful'].append(file_id)
                return True
            else:
                response_text = await response.text()
                results['failed'].append({
                    'file_id': file_id,
                    'error': f"HTTP {response.status}: {response_text}"
                })
                return False
    except Exception as e:
        results['failed'].append({
            'file_id': file_id,
            'error': f"Exception: {str(e)}"
        })
        return False


# Function to close handles sent by the Web UI (optimized for parallel execution).
@app.route('/close_handles', methods=['POST'])
@requires_auth
async def close_handles():
    data = await request.get_json()
    file_ids = data['file_ids']

    # Validate and prepare handles
    handles_to_close = []
    not_found = []

    for file_id in file_ids:
        handle = find_handle(str(file_id))
        if handle:
            handles_to_close.append((str(file_id), handle))
        else:
            not_found.append(str(file_id))

    if not handles_to_close:
        return jsonify({
            "error": "No valid handles found",
            "not_found": not_found
        }), 404

    # Track results
    results = {
        'successful': [],
        'failed': [],
        'not_found': not_found
    }

    # Close all handles concurrently with batching for safety (100 at a time)
    batch_size = 100
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(handles_to_close), batch_size):
            batch = handles_to_close[i:i + batch_size]
            tasks = [
                close_single_handle(session, file_id, handle, results)
                for file_id, handle in batch
            ]
            # Execute batch concurrently with error handling
            await asyncio.gather(*tasks, return_exceptions=True)

    # Update Redis cache - remove successfully closed locks
    if results['successful']:
        open_files_raw = redis_db.get('open_files')
        open_locks_raw = redis_db.get('smb_locks')

        if open_files_raw and open_locks_raw:
            open_files = decompress_json(open_files_raw)
            open_locks = decompress_json(open_locks_raw)

            # Remove closed files from cache
            for file_id in results['successful']:
                if file_id in open_files:
                    del open_files[file_id]

            # Remove closed locks from grants list
            open_locks['grants'] = [
                grant for grant in open_locks.get('grants', [])
                if grant['file_id'] not in results['successful']
            ]

            # Update Redis with cleaned data
            redis_db.set('open_files', compress_json(open_files))
            redis_db.set('smb_locks', compress_json(open_locks))

    # Build response message
    total_requested = len(file_ids)
    total_successful = len(results['successful'])
    total_failed = len(results['failed'])
    total_not_found = len(results['not_found'])

    if total_failed == 0 and total_not_found == 0:
        return jsonify({
            "message": f"Successfully released {total_successful} lock(s)",
            "successful": total_successful,
            "failed": 0,
            "not_found": 0
        }), 200
    else:
        return jsonify({
            "message": f"Released {total_successful} of {total_requested} lock(s)",
            "successful": total_successful,
            "failed": total_failed,
            "not_found": total_not_found,
            "failed_details": results['failed'][:10],  # Limit error details to first 10
            "not_found_ids": results['not_found'][:10]
        }), 207  # 207 Multi-Status for partial success

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
