import logging
import pytest
import rtrlib

from retrying import retry, RetryError
from time import time
from operator import attrgetter
import krill_ca_api as krill_ca_api_lib
import krill_pub_api as krill_pub_api_lib

from tests.util import krill
from tests.util.docker import docker_project, class_service_manager, function_service_manager, run_command, docker_host_fqdn
from tests.util.krill import krill_api_config
from tests.util.rtr import rtr_fetch_one, roa_to_roa_string
from tests.util.relyingparties import *

from data import *


# Test classes that use this fixture will cause Krill and its dependencies to
# be started (and torn down at the end of all tests in the class), and to be
# configured with CAs and ROas. If you want many test classes to use the
# created resources before they are torn down module scope might then be more
# appropriate.
@pytest.fixture(scope="class")
def krill_with_roas(docker_project, krill_api_config, class_service_manager):
    #
    # Define some retry helpers for situations where the API call to Krill
    # can succeed but Krill may not yet be in the expected state.
    #
    def no_retry_if_forbidden(e):
        """Return True if we should retry, False otherwise"""
        return not (isinstance(e, krill_ca_api_lib.ApiException) and e.status == 403)

    def retry_if_not(result):
        """Return True if we should retry, False otherwise"""
        # e.g. return True for empty lists, empty strings, None
        return not bool(result)

    @retry(
        stop_max_attempt_number=10,
        wait_fixed=2000,
        retry_on_exception=no_retry_if_forbidden,
        wrap_exception=True)
    def wait_until_ready():
        return krill_other_api.is_authorized()

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=1000,
        wait_exponential_max=10000,
        retry_on_result=retry_if_not,
        wrap_exception=True)
    def wait_until_ca_has(ca_handle, property, matcher_func):
        ca = krill_ca_api.get_ca(ca_handle)
        f = attrgetter(property)
        cas = f(ca)
        return [ca for ca in cas if matcher_func(ca)]

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=1000,
        wait_exponential_max=10000,
        retry_on_result=retry_if_not,
        wrap_exception=True)
    def wait_until_child_ca_has_at_least_one(parent_handle, child_handle, property):
        ca = krill_ca_api.get_child_ca(parent_handle, child_handle)
        f = attrgetter(property)
        return f(ca)

    @retry(
        stop_max_attempt_number=10,
        wait_exponential_multiplier=1000,
        wait_exponential_max=10000,
        retry_on_result=retry_if_not,
        wrap_exception=True)
    def wait_until_ca_has_resources(ca_handle, asn, v4, v6):
        ca = krill_ca_api.get_ca(ca_handle)
        f = attrgetter("resources")
        res = f(ca)
        return set(res.asn) == set(asn) and set(res.v4) == set(v4) and set(res.v6) == set(v6)

    #
    # define some helper functions
    #
    def add_ca(ca_handle):
        logging.info(f'-> Adding CA "{ca_handle}"')
        krill_ca_api.add_ca(krill_ca_api_lib.AddCARequest(ca_handle))

        logging.info(f'-> Getting RFC 8183 publisher request for CA "{ca_handle}" (API call `get_ca_publisher_request()`)')
        rfc8183_request = krill_ca_api.get_ca_publisher_request(ca_handle, format='json')

        logging.info(f'-> Submitting RFC 8183 publisher request for CA "{ca_handle}" in exchange for an RFC 8183 repository_response (API call `add_publisher()`)')
        rfc8183_response = krill_pub_api.add_publisher(rfc8183_request)

        logging.info(f'-> Submitting RFC 8181 repository response for CA "{ca_handle}" (API call `update_ca_repository()`)')
        krill_ca_api.update_ca_repository(
            ca_handle,
            inline_object=krill_ca_api_lib.InlineObject(repository_response=rfc8183_response))
        logging.info(f'-> Added CA "{ca_handle}"')

    def link_child_ca_under_parent_ca(child_ca_handle, parent_ca_handle, resources):
        logging.info(f'-> Getting RFC 8183 child request for CA "{child_ca_handle}" (API call `get_ca_child_request()`)')
        rfc8183_request = krill_ca_api.get_ca_child_request(child_ca_handle, format="json")

        logging.info(f'-> Adding CA "{child_ca_handle}" as a child of "{parent_ca_handle}" (API call `add_child_ca()`)')
        req = krill_ca_api_lib.AddCAChildRequest(
            handle=child_ca_handle,
            resources=resources,
            id_cert=rfc8183_request.id_cert)
        krill_ca_api.add_child_ca(parent_ca_handle, req)
        logging.info(f'-> Added CA "{child_ca_handle} as a child of "{parent_ca_handle}"')

        logging.info(f'-> Waiting for CA "{child_ca_handle}" to be registered as a child of "{parent_ca_handle}"')
        wait_until_ca_has(parent_ca_handle, 'children', lambda handle: handle == child_ca_handle)

        logging.info(f'-> Waiting for resources of child CA "{child_ca_handle}" to be registered')
        wait_until_child_ca_has_at_least_one(parent_ca_handle, child_ca_handle, 'entitled_resources.asn')

    def link_parent_ca_above_child_ca(parent_ca_handle, child_ca_handle, resources):
        logging.info(f'-> Getting RFC 8183 parent response for CA "{child_ca_handle}" (API call `get_child_ca_parent_contact()`)')
        rfc8183parentresponse = krill_ca_api.get_child_ca_parent_contact(parent_ca_handle, child_ca_handle)

        logging.info(f'-> Adding CA "{parent_ca_handle}" as a parent of "{child_ca_handle}" (API call `add_ca_parent()`)')
        req = krill_ca_api_lib.AddParentCARequest(
            handle=parent_ca_handle,
            contact=rfc8183parentresponse)
        krill_ca_api.add_ca_parent(child_ca_handle, req)
        logging.info(f'-> Added CA "{parent_ca_handle}" as a parent of "{child_ca_handle}"')

        logging.info(f'-> Waiting for CA "{parent_ca_handle}" to be registered as a parent of "{child_ca_handle}"')
        wait_until_ca_has(child_ca_handle, 'parents', lambda ca: ca.handle == parent_ca_handle)

        logging.info(f'-> Waiting for resources of CA "{child_ca_handle}" to be issued:')
        wait_until_ca_has_resources(child_ca_handle, resources.asn, resources.v4, resources.v6)

    #
    # Go!
    #

    try:
        # Bring up Krill and its dependencies
        krill.select_krill_config_file(docker_project, 'krill.conf')
        class_service_manager.start_services_with_dependencies(docker_project, ['krill'])

        # Strategy: Test then add, don't add then handle failure because that will
        # cause errors to appear in the Krill server log which can be confusing
        # when investigating problems.

        # Get the API helper objects we need
        krill_ca_api_client = krill_ca_api_lib.ApiClient(krill_api_config)
        krill_ca_api = krill_ca_api_lib.CertificateAuthoritiesApi(krill_ca_api_client)
        krill_roa_api = krill_ca_api_lib.RouteAuthorizationsApi(krill_ca_api_client)
        krill_other_api = krill_ca_api_lib.OtherApi(krill_ca_api_client)

        krill_pub_api_client = krill_pub_api_lib.ApiClient(krill_api_config)
        krill_pub_api = krill_pub_api_lib.PublishersApi(krill_pub_api_client)

        # Define the CA handles that we will work with
        ta_handle = 'ta'
        parent_handle = 'parent'
        child_handle = 'child'

        # Ensure that Krill is ready for our attempts to communicate with it
        logging.info('Wait till we can connect to Krill...')
        wait_until_ready()

        #
        # Create the desired state inside Krill
        #

        parent_resources = krill_ca_api_lib.Resources(asn=KRILL_PARENT_ASNS, v4=KRILL_PARENT_IPV4S, v6=KRILL_PARENT_IPV6S)
        child_resources = krill_ca_api_lib.Resources(asn=KRILL_CHILD_ASNS, v4=KRILL_CHILD_IPV4S, v6=KRILL_CHILD_IPV6S)

        logging.info(f'Checking if Krill has an embedded TA "{ta_handle}"')
        ca_handles = [ca.handle for ca in krill_ca_api.list_cas().cas]

        if ta_handle in ca_handles:
            logging.info(f'Configuring Krill for use with embedded TA "{ta_handle}"')

            logging.info(f'Adding CA "{parent_handle}" if not already present')
            if not parent_handle in ca_handles:
                add_ca(parent_handle)

            logging.info(f'Creating TA "{ta_handle}" -> CA "{parent_handle}" relationship if not already present')
            ta_children = krill_ca_api.get_ca(ta_handle).children
            if not parent_handle in ta_children:
                link_child_ca_under_parent_ca(parent_handle, ta_handle, parent_resources)

            logging.info(f'Creating TA "{ta_handle}" <- CA "{parent_handle}" relationship if not already present')
            if len(krill_ca_api.get_ca(parent_handle).parents) == 0:
                link_parent_ca_above_child_ca(ta_handle, parent_handle, parent_resources)

            logging.info(f'Adding CA "{child_handle}" if not already present')
            if not child_handle in ca_handles:
                add_ca(child_handle)

            logging.info(f'Creating CA "{parent_handle}" -> CA "{child_handle}" relationship if not already present')
            if len(krill_ca_api.get_ca(parent_handle).children) == 0:
                link_child_ca_under_parent_ca(child_handle, parent_handle, child_resources)

            logging.info(f'Creating CA "{parent_handle}" <- CA "{child_handle}" relationship if not already present')
            if len(krill_ca_api.get_ca(child_handle).parents) == 0:
                link_parent_ca_above_child_ca(parent_handle, child_handle, child_resources)

            logging.info(f'Creating CA "{child_handle}" ROAs if not already present')
            if len(krill_roa_api.list_route_authorizations(child_handle)) == 0:
                delta = krill_ca_api_lib.ROADelta(added=TEST_ROAS, removed=[])

                @retry(
                    stop_max_attempt_number=10,
                    wait_exponential_multiplier=1000,
                    wait_exponential_max=10000,
                    wrap_exception=True)
                def update_roas():
                    logging.info('Updating ROAs...')
                    krill_roa_api.update_route_authorizations(child_handle, delta)

                update_roas()

        logging.info('Krill configuration complete')
    except RetryError as e:
        if e.last_attempt.has_exception:
            (ex_type, ex_value, traceback) = e.last_attempt.value
            pytest.fail(f'Retries exhausted while configuring Krill: {ex_value} caused by {e}')
        else:
            pytest.fail(f'Retries exhausted while configuring Krill: {e}')

    yield (krill_ca_api_client, krill_pub_api_client)


@pytest.mark.usefixtures("krill_with_roas")
class TestKrillWithRelyingParties:
    def test_setup(self):
        # Cause the krill_with_roas and dependent fixtures to be setup once
        # before the tests below run, otherwise the first real test also
        # includes the work and output of creating the fixtures.
        pass

    #@pytest.mark.parametrize("service", [Routinator, RoutinatorUnstable, FortValidator, OctoRPKI, Rcynic, RPKIClient, RPKIValidator3])
    @pytest.mark.parametrize("service", [Routinator, RoutinatorUnstable, FortValidator, OctoRPKI, Rcynic, RPKIClient])
    def test_rtr(self, docker_host_fqdn, docker_project, function_service_manager, service, metadata):
        #
        # Use Docker Compose to deploy the given Relying Party service and its dependencies.
        # On tear down the service container and its dependent containers will be killed and removed.
        #
        function_service_manager.start_services_with_dependencies(docker_project, service.name)

        class UpdateWasEmpty(Exception):
            pass

        def retry_if_incomplete_update(exception):
            return isinstance(exception, rtrlib.exceptions.SyncTimeout) or \
                   isinstance(exception, UpdateWasEmpty)

        @retry(
            stop_max_attempt_number=10,
            wait_exponential_multiplier=5000,
            wait_exponential_max=20000,
            retry_on_exception=retry_if_incomplete_update,
            wrap_exception=True)
        def fetch_from_rtr_server():
            try:
                rtr_start_time = int(time())
                logging.info(f'Connecting RTR client to {docker_host_fqdn}:{service.rtr_port}')
                received_roas = set(rtr_fetch_one(docker_host_fqdn, service.rtr_port, service.rtr_timeout_seconds))
                rtr_elapsed_time = int(time()) - rtr_start_time
    
                # r is now a list of PFXRecord
                # see: https://python-rtrlib.readthedocs.io/en/latest/api.html#rtrlib.records.PFXRecord
                logging.info(f'Received {len(received_roas)} ROAs via RTR from {service.name} in {rtr_elapsed_time} seconds')

                if len(received_roas) == 0:
                    # retry, maybe the ROAs are not available yet
                    raise UpdateWasEmpty()
    
                # are each of the TEST_ROAS items in r?
                # i.e. is the intersection of the two sets equal to that of the TEST_ROAS set?
    
                logging.info(f'Comparing {len(received_roas)} received ROAs to {len(TEST_ROAS)} expected ROAs...')
                expected_roas = set([roa_to_roa_string(r) for r in TEST_ROAS])
                assert received_roas == expected_roas
            except rtrlib.exceptions.SyncTimeout as e:
                logging.error(f'Timeout (>{service.rtr_timeout_seconds} seconds) while syncing RTR with {service.name} at {docker_host_fqdn}:{service.rtr_port}')
                try:
                    if not service.is_ready():
                        logging.error(f'{service.name} is not ready')
                except Exception as innerE:
                    logging.error(f'Unable to determine if {service.name} is ready: {innerE}')
    
                raise e

        fetch_from_rtr_server()
