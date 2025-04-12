import examples.webdavServer.server as server
import logging, os

basedir = os.path.dirname(__file__)
shared_dir = os.path.join(basedir, 'examples', 'webdavServer', 'shared_dir_tmp')

if __name__ == "__main__":
    if input('Press Any key to continue (except N/n): ').lower() == 'n': quit()
    if not os.path.exists(shared_dir): os.mkdir(shared_dir)
    server.run_server(
        shared_dir=shared_dir,
        readonly=False,
        host='0.0.0.0',
        port=8080,
        verbose=logging.NOTSET
    )