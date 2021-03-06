import logging
import threading
import gflags
from ct.cert_analysis import all_checks
from ct.client import reporter
from Queue import Queue

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("cert_db_writer_queue_size", 10, "Size of certificate "
                      "queue in db reporter")


class CertDBCertificateReport(reporter.CertificateReport):
    def __init__(self, cert_db, log_key, checks=all_checks.ALL_CHECKS):
        self._cert_db = cert_db
        self.log_key = log_key
        self._certs_queue = Queue(FLAGS.cert_db_writer_queue_size)
        self._writer = None
        super(CertDBCertificateReport, self).__init__(checks=checks)

    def report(self):
        super(CertDBCertificateReport, self).report()
        self._certs_queue.join()
        logging.info("Finished scheduled writing to CertDB")
        self._certs_queue.put(None)
        self.reset()

    def reset(self):
        if self._writer:
            self._writer.join()
            self._writer = None


    def _batch_scanned_callback(self, result):
        if not self._writer:
            self._writer = threading.Thread(target=_process_certs,
                                            args=(self._cert_db, self.log_key,
                                                  self._certs_queue))
            self._writer.start()
        self._certs_queue.put([(desc, index) for desc, index, _ in result])


def _process_certs(db, log_key, certs_queue):
    while True:
        certs = certs_queue.get()
        if certs is None:
            certs_queue.task_done()
            break
        db.store_certs_desc(certs, log_key)
        certs_queue.task_done()
