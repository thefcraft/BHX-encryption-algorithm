import logging #; logging.basicConfig(level=logging.DEBUG)

from cheroot import wsgi
import stat
from wsgidav import util
from wsgidav.wsgidav_app import WsgiDAVApp
from wsgidav.dav_error import HTTP_FORBIDDEN, DAVError, HTTP_UNAUTHORIZED
from wsgidav.fs_dav_provider import FilesystemProvider, FileResource, FolderResource, BUFFER_SIZE
from wsgidav.dc.base_dc import BaseDomainController

import os, shutil, sys
from typing import List
from BHX import BHX, decode_filename, encode_filename
from BHX.io import BHXByteIO#, BHXBytesIOWriter, BHXStreamWriter
from BHX.logger import monitor__get__attributes__

# BHXByteIO.__getattribute__ = monitor__get__attributes__
# BHXBytesIOWriter.__getattribute__ = monitor__get__attributes__
# BHXStreamWriter.__getattribute__ = monitor__get__attributes__

# bhx_password = b'safe key' # for later use the user password
# if you wrote right password then only you can see the data
# TODO readonly acess for wrong password ?

class CustomFileResource(FileResource):
    def __init__(self, path, environ, file_path):
        bhx_password:str = environ['wsgidav.customauth.password']
        self.bhx = BHX(key=bhx_password.encode(), use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        super().__init__(path, environ, file_path)
        
    def get_display_name(self):
        return decode_filename(self.bhx, self.name)
    
    def get_content_type(self) -> str:
        return util.guess_mime_type(self.get_display_name())
    
    def get_etag(self):
        etag = util.get_file_etag(self._file_path) # this is file 
        etag = etag[:-len(f'-{self.get_content_length() + 16}')]
        return f'{etag}-{self.get_content_length()}'
    
    def get_content_length(self):
        return self.file_stat[stat.ST_SIZE] - 16
    
    def get_content(self):
        assert not self.is_collection
        return BHXByteIO(open(self._file_path, "r+b", BUFFER_SIZE), bhx=self.bhx, close_file_on_close=True)
    
    def begin_write(self, *, content_type=None):
        assert not self.is_collection
        if self.provider.readonly:
            raise DAVError(HTTP_FORBIDDEN)
        return BHXByteIO(open(self._file_path, 'w+b', BUFFER_SIZE), bhx=self.bhx, close_file_on_close=True)
        # return BHXStreamWriter(open(self._file_path, 'wb', BUFFER_SIZE), bhx=self.bhx, close_file_on_close=True)
        # return open(r"C:\ThefCraft\thefcraft-github\ftp-server-client-for-tfbin\abc.txt", "wb", BUFFER_SIZE)
    
class CustomFolderResource(FolderResource):
    def __init__(self, path, environ, file_path):
        bhx_password:str = environ['wsgidav.customauth.password']
        self.bhx = BHX(key=bhx_password.encode(), use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        super().__init__(path, environ, file_path)

    # def get_member_names(self) -> List[str]:
        # names = super().get_member_names()
        # return [decode_filename(self.bhx, name) for name in names]
    
    def get_display_name(self):
        return decode_filename(self.bhx, self.name)
    
    def get_member(self, name: str) -> CustomFileResource:
        assert util.is_str(name), f"{name!r}"
        fp = os.path.join(self._file_path, util.to_str(name))
        path = util.join_uri(self.path, decode_filename(self.bhx, name))
        # path = util.join_uri(self.path, name)
        res = None
        
        if os.path.isdir(fp):
            res = CustomFolderResource(path, self.environ, fp)
        elif os.path.isfile(fp):
            res = CustomFileResource(path, self.environ, fp)
        return res
    
    def create_empty_resource(self, name):
        assert "/" not in name
        if self.provider.readonly:
            raise DAVError(HTTP_FORBIDDEN)
        path = util.join_uri(self.path, name)
        fp = self.provider._loc_to_file_path(path, self.environ)
        f = BHXByteIO(open(fp, "w+b"), bhx=self.bhx, close_file_on_close=True)
        f.close()
        return self.provider.get_resource_inst(path, self.environ)
     
class CustomFilesystemProvider(FilesystemProvider):
    def __init__(self, root_folder, *, readonly=False, fs_opts=None):
        super().__init__(root_folder, readonly=readonly, fs_opts=fs_opts)
    def _loc_to_file_path(self, path: str, environ: dict = None):
        bhx_password:str = environ['wsgidav.customauth.password']
        bhx = BHX(key=bhx_password.encode(), use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        root_path = self.root_folder_path
        assert root_path is not None
        assert util.is_str(root_path)
        assert util.is_str(path)
        path_parts = path.strip("/").split("/")
        
        path_parts = [encode_filename(bhx, part) if part != '' else part for part in path_parts]
        
        file_path = os.path.abspath(os.path.join(root_path, *path_parts))
        if not file_path.startswith(root_path):
            raise RuntimeError(
                f"Security exception: tried to access file outside root: {file_path}"
            )
        file_path = util.to_unicode_safe(file_path)
        return file_path
    def get_resource_inst(self, path: str, environ: dict) -> FileResource:
        self._count_get_resource_inst += 1
        fp = self._loc_to_file_path(path, environ)
        if not os.path.exists(fp):
            return None
        if not self.fs_opts.get("follow_symlinks") and os.path.islink(fp):
            raise DAVError(HTTP_FORBIDDEN, f"Symlink support is disabled: {fp!r}")
        if os.path.isdir(fp):
            return CustomFolderResource(path, environ, fp)
        return CustomFileResource(path, environ, fp)


class CustomDomainController(BaseDomainController):
    def __init__(self,  wsgidav_app, config):
        self.realm = "CustomRealm"
    def get_domain_realm(self, path_info, environ) -> str: return self.realm
    def require_authentication(self, realmname, environ) -> bool: return True # Require authentication always
    def is_realm_user(self, realmname, username, environ) -> bool: return username == "admin" # Allow only "admin"
    def basic_auth_user(self, realmname, username, password, environ) -> bool:
        if username != "admin": return False
        environ["wsgidav.customauth.password"] = password
        return True # Accept any password for admin
    def supports_http_digest_auth(self) -> bool: return False # Use basic auth only

config = {
    
    # "simple_dc": {
    #     # "user_mapping": {"*": True} # Anonymous access
    #     "user_mapping": {
    #         "*": {
    #             "admin": {"password": "adminpass"},
    #         }
    #     }
    # },
    "http_authenticator": {
        "domain_controller": f"{__name__}.CustomDomainController",
        "accept_basic": True,
        "accept_digest": False,
        "default_to_digest": False,
        "trusted_auth_header": None,
    },
}

def run_server(shared_dir: str, readonly: bool = False, host: str = "0.0.0.0", port: int=8080, verbose: int = logging.NOTSET):
    config["host"] = host
    config["port"] = port
    config["verbose"] = verbose
    config["provider_mapping"] = {
        "/": CustomFilesystemProvider(shared_dir, readonly=readonly) # for now readonly
    }
    
    app = WsgiDAVApp(config)
    server = wsgi.Server((config["host"], config["port"]), app)
    print("Starting WsgiDAV server on:")
    print(f"\thttp://{host}:{port}")
    try:
        import psutil, socket
        # Use psutil to get all network interfaces and IPs
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    print(f"\thttp://{addr.address}:{port} ({interface})")
    except Exception as e:
        import warnings
        warnings.warn(
            f"error while printing ip addrs (try install psutil), Error: {e}",
            Warning,
            stacklevel=0
        )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("Server stopped.")

if __name__ == "__main__":
    shared_dir = os.path.join(os.path.dirname(__file__), 'shared_dir_tmp')
    if not os.path.exists(shared_dir): os.mkdir(shared_dir)
    run_server(shared_dir = shared_dir)
