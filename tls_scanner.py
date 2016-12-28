#!/usr/bin/python3

# Author: Maxwell Morgan
# Date: 2016-12-26
# Purpose: A class to perform TLS configuration recon on domain name
# Todo: - mark signal alarm to zero before any exceptions are raised

# Modules
##############################################################################
import requests
import signal


class ScannerError(Exception):
    """Base class for exceptions in this module"""
    pass


class ScanFrequencyError(ScannerError):
    """
    Exception raised for errors relating to too many scans being requested
    on a short interval

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        self.message = message


class TLSScanner():
    """
    A object representing a TLS configuration scanner. A wrapper around
    the TLS observatory API provided by mozilla foundation
    """
    # POST request w/ params: target={}&rescan={}
    REQ_SCAN_API = ("https://tls-observatory.services.mozilla.com/api"
                    "/v1/scan")
    POST_VALS = {'target': '',
                 'rescan': ''}

    # GET request w/ params: id={}
    GET_RES_API = ("https://tls-observatory.services.mozilla.com/api/v1/"
                   "results")
    GET_VALS = {'id': ''}

    _hostname = None
    _scan_id = None
    _scan_complete = False
    _scan_result = None

    def __init__(self, hostname=None):
        if hostname is not None:
            self._hostname = hostname
            self._scan_id = None
            self._scan_complete = False
            self._scan_result = None

    @staticmethod
    def _scan_timeout_handler(signum, frame):
        raise TimeoutError("Scan timed out...")

    def _get_scan_results(self):
        if self._hostname is None:
            raise ValueError("No hostname set...")

        get_params = self.GET_VALS
        get_params['id'] = self._scan_id
        # request the results from the url API
        try:
            req = requests.get(self.GET_RES_API, params=get_params)
        except requests.exceptions.ConnectionError as err:
            print("Connection failure while attempting to retrieve "
                  "scan results for host {}",
                  host)
            signal.alarm(0)
            raise err
        except requests.exceptions.Timeout as err:
            print("Timeout while attempting to retrieve scan results "
                  "for host {}", host)
            signal.alarm(0)
            raise err

        try:
            self._scan_result = req.json()
        except ValueError as err:
            print("Could not parse JSON object from scan API "
                  "for host {}", host)
            signal.alarm(0)
            raise err

        if self._scan_result['completion_perc'] == 100:
            self._scan_complete = True

    def _start_scan(self, rescan, timeout):
        post_params = self.POST_VALS
        post_params['target'] = self._hostname
        post_params['rescan'] = 'true' if rescan else 'false'
        # schedule scan
        try:
            req = requests.post(self.REQ_SCAN_API, data=post_params,
                                timeout=timeout)
        except requests.exceptions.ConnectionError as err:
            print("Connection failure while attempting to scan {}", host)
            signal.alarm(0)
            raise err
        except requests.exceptions.Timeout as err:
            print("Timeout while attempting to scan {}", host)
            signal.alarm(0)
            raise err
        if req.text.startswith("Last scan for target"):
            # raise custom exception to notify user of too frequent scans
            signal.alarm(0)
            raise ScanFrequencyError("Too many scans requested in the past 3 "
                                     "minutes... Try again soon or set rescan "
                                     "to false to obtain previous results")

        # get scan ID
        try:
            self._scan_id = req.json()['scan_id']
        except ValueError as err:
            print("Could not parse JSON object from scan API "
                  "for host {}".format(self._hostname))
            raise err

    def run_scan(self, rescan=False, timeout=0):
        # start a signaled timeout exception
        if timeout != 0:
            signal.signal(signal.SIGALRM, self._scan_timeout_handler)
            signal.alarm(timeout)

        if self._hostname is None:
            raise ValueError("Hostname must be specified String values...")

        self._start_scan(rescan, timeout)

        while not self._scan_complete:
            self._get_scan_results()

        # disable alarm if it was set
        signal.alarm(0)
        return self._scan_result
