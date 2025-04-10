from cheroot import wsgi
import stat
from wsgidav import util
from wsgidav.wsgidav_app import WsgiDAVApp
from wsgidav.dav_error import HTTP_FORBIDDEN, DAVError
from wsgidav.fs_dav_provider import FilesystemProvider, FileResource, FolderResource, BUFFER_SIZE
import os, shutil, sys
from typing import List
from BHX import BHX, decode_filename, encode_filename
from BHX.io import BHXBytesIOReader, BHXStreamWriter
from BHX.logger import monitor__get__attributes__

BHXBytesIOReader.__getattribute__ = monitor__get__attributes__
BHXStreamWriter.__getattribute__ = monitor__get__attributes__

bhx_password = b'safe key' # for later use the user password

shared_dir = os.path.join(os.path.dirname(__file__), 'shared_dir')

class CustomFileResource(FileResource):
    def __init__(self, path, environ, file_path):
        self.bhx = BHX(key=bhx_password, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
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
        return BHXBytesIOReader(open(self._file_path, "rb", BUFFER_SIZE), bhx=self.bhx, close_file_on_close=True)
    
    def begin_write(self, *, content_type=None):
        assert not self.is_collection
        if self.provider.readonly:
            raise DAVError(HTTP_FORBIDDEN)
        return BHXStreamWriter(open(self._file_path, 'wb', BUFFER_SIZE), bhx=self.bhx, close_file_on_close=True)
        # return open(r"C:\ThefCraft\thefcraft-github\ftp-server-client-for-tfbin\abc.txt", "wb", BUFFER_SIZE)
    
class CustomFolderResource(FolderResource):
    def __init__(self, path, environ, file_path):
        self.bhx = BHX(key=bhx_password, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        super().__init__(path, environ, file_path)

    # def get_member_names(self) -> List[str]:
        # names = super().get_member_names()
        # return [decode_filename(self.bhx, name) for name in names]
    
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
        f = BHXStreamWriter(open(fp, "wb"), bhx=self.bhx, close_file_on_close=True)
        f.close()
        return self.provider.get_resource_inst(path, self.environ)
     
class CustomFilesystemProvider(FilesystemProvider):
    def __init__(self, root_folder, *, readonly=False, fs_opts=None):
        self.bhx = BHX(key=bhx_password, use_new_key_depends_on_old_key=False, use_bcrypt=False, use_hmac=False)
        super().__init__(root_folder, readonly=readonly, fs_opts=fs_opts)
    def _loc_to_file_path(self, path: str, environ: dict = None):
        root_path = self.root_folder_path
        assert root_path is not None
        assert util.is_str(root_path)
        assert util.is_str(path)
        path_parts = path.strip("/").split("/")
        
        path_parts = [encode_filename(self.bhx, part) if part != '' else part for part in path_parts]
        
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

config = {
    "host": "127.0.0.1",
    "port": 8080,
    "provider_mapping": {
        "/": CustomFilesystemProvider(shared_dir, readonly=False) # for now readonly
        # "/": shared_dir
    },  # Serve the current directory
    "simple_dc": {
        "user_mapping": {"*": True} # Anonymous access
    },  
    "verbose": 1,
}

def run_server():
    app = WsgiDAVApp(config)
    server = wsgi.Server((config["host"], config["port"]), app)

    print(f"Starting WsgiDAV server on {config['host']}:{config['port']}...")
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("Server stopped.")

if __name__ == "__main__":
    run_server()
