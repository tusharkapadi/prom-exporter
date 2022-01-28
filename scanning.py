import time
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily
from prometheus_client import start_http_server
import json
import logging
import requests
import os
from datetime import datetime
from datetime import timedelta

from sdcclient import SdScanningClient

secure_api_token = os.getenv('SECURE_API_TOKEN').replace('\n', '')
secure_url = os.getenv('SECURE_URL')
scheduled_run_minutes = int(os.getenv('SCHEDULED_RUN_MINUTES'))
prom_exp_url_port = int(os.getenv('PROM_EXP_URL_PORT'))
batch_limit = int(os.getenv('BATCH_LIMIT'))



first_time_running = True



last_run_date = datetime.now()
last_run_date_str = last_run_date.strftime("%d/%m/%Y %H:%M")

status_list = ["pass", "fail", "unknown"]

scanning_prom_exp_metrics = {}
all_compliances = []
all_benchmarks = []


class SecureMetricsCollector(object):
    def __init__(self):
        pass

    def collect(self):

        # Scanning
        prom_metric_scanning_images = GaugeMetricFamily("sysdig_secure_images_scanned",
                                                        'All the images detected in your cluster with scan result.',
                                                        labels=['sysdig_secure_image_distro',
                                                                'sysdig_secure_image_scan_origin',
                                                                'sysdig_secure_image_reg_name',
                                                                'sysdig_secure_image_repo_name',
                                                                'sysdig_secure_image_status',
                                                                'sysdig_secure_image_running',
                                                                'sysdig_secure_containers',
                                                                'sysdig_secure_cluster'
                                                                ])

        # Compliance
        prom_metric_compliance_pass = GaugeMetricFamily("sysdig_secure_compliance_pass",
                                                        'How many controls passed against the compliance.',
                                                        labels=['sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_standard'])

        prom_metric_compliance_fail = GaugeMetricFamily("sysdig_secure_compliance_fail",
                                                        'How many controls failed against the compliance.',
                                                        labels=['sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_standard'])

        prom_metric_compliance_checked = GaugeMetricFamily("sysdig_secure_compliance_checked",
                                                           'How many controls checked against the compliance.',
                                                           labels=['sysdig_secure_compliance_type',
                                                                   'sysdig_secure_compliance_standard'])

        prom_metric_compliance_unchecked = GaugeMetricFamily("sysdig_secure_compliance_unchecked",
                                                             'How many controls unchecked against the compliance.',
                                                             labels=['sysdig_secure_compliance_type',
                                                                     'sysdig_secure_compliance_standard'])

        # Benchmarks
        prom_metric_benchmark_pass = GaugeMetricFamily("sysdig_secure_benchmark_resources_pass",
                                                       'How many resources  passed against the benchmark.',
                                                       labels=['sysdig_secure_platform', 'sysdig_secure_benchmark_name',
                                                               'sysdig_secure_benchmark_schema'])

        prom_metric_benchmark_fail = GaugeMetricFamily("sysdig_secure_benchmark_resources_fail",
                                                       'How many resources failed against the benchmark.',
                                                       labels=['sysdig_secure_platform', 'sysdig_secure_benchmark_name',
                                                               'sysdig_secure_benchmark_schema'])

        prom_metric_benchmark_warn = GaugeMetricFamily("sysdig_secure_benchmark_resources_warn",
                                                       'How many resources warn against the benchmark.',
                                                       labels=['sysdig_secure_platform', 'sysdig_secure_benchmark_name',
                                                               'sysdig_secure_benchmark_schema'])

        curr_date = datetime.now()
        curr_date_str = curr_date.strftime("%d/%m/%Y %H:%M")

        global last_run_date
        global last_run_date_str
        global first_time_running

        global scanning_prom_exp_metrics
        global all_compliances
        global all_benchmarks

        next_run_date = last_run_date + timedelta(minutes=scheduled_run_minutes)
        next_run_date_str = next_run_date.strftime("%d/%m/%Y %H:%M")

        print (" last_run_date_str - " + last_run_date_str)
        print (" curr_date_str - " + curr_date_str)
        print (" next_run_date_str - " + next_run_date_str)

        if next_run_date > curr_date and not first_time_running:
            print ("Skipping querying......")
            print ("Returning metrics from memory")
            for x in scanning_prom_exp_metrics.keys():
                temp_string = x.split("|")
                prom_metric_scanning_images.add_metric(
                    [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                     temp_string[6], temp_string[7]],
                    scanning_prom_exp_metrics[x])
            yield prom_metric_scanning_images

            print ("all compliance length - " + str(len(all_compliances)))
            for compliance in all_compliances:
                prom_metric_compliance_pass.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                       compliance["pass"])
                prom_metric_compliance_fail.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                       compliance["fail"])
                prom_metric_compliance_checked.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                          compliance["checked"])
                prom_metric_compliance_unchecked.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                            compliance["unchecked"])

            yield prom_metric_compliance_pass
            yield prom_metric_compliance_fail
            yield prom_metric_compliance_checked
            yield prom_metric_compliance_unchecked

            print ("all benchmarks length - " + str(len(all_benchmarks)))
            for benchmark in all_benchmarks:
                prom_metric_benchmark_pass.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                      benchmark["pass"])
                prom_metric_benchmark_fail.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                      benchmark["fail"])
                prom_metric_benchmark_warn.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                      benchmark["warn"])

            yield prom_metric_benchmark_pass
            yield prom_metric_benchmark_fail
            yield prom_metric_benchmark_warn

            return

        print ("Querying metrics from Sysdig Secure....")

        print ("scheduled_run_minutes = " + str(scheduled_run_minutes))

        last_run_date = curr_date
        next_run_date = curr_date + timedelta(minutes=scheduled_run_minutes)

        try:
            scanning_prom_exp_metrics = scanning_prom_exporter()
        except Exception as ex:
            logging.error(ex)
            return

        print ("scanning_prom_exp_metrics count - " + str(len(scanning_prom_exp_metrics)))

        for x in scanning_prom_exp_metrics.keys():
            temp_string = x.split("|")
            prom_metric_scanning_images.add_metric(
                [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                 temp_string[6], temp_string[7]],
                scanning_prom_exp_metrics[x])
        yield prom_metric_scanning_images

        print ("yielded scanning prom exporter")

        # compliance
        all_compliances = compliance_prom_exporter()

        print ("all compliance count - " + str(len(all_compliances)))

        for compliance in all_compliances:
            prom_metric_compliance_pass.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                   compliance["pass"])
            prom_metric_compliance_fail.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                   compliance["fail"])
            prom_metric_compliance_checked.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                      compliance["checked"])
            prom_metric_compliance_unchecked.add_metric([compliance["compliance_type"], compliance["standard"]],
                                                        compliance["unchecked"])

        yield prom_metric_compliance_pass
        yield prom_metric_compliance_fail
        yield prom_metric_compliance_checked
        yield prom_metric_compliance_unchecked

        print ("yielded compliance prom exporter")

        # Benchmarks

        all_benchmarks = benchmark_prom_exporter()

        for benchmark in all_benchmarks:
            prom_metric_benchmark_pass.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                  benchmark["pass"])
            prom_metric_benchmark_fail.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                  benchmark["fail"])
            prom_metric_benchmark_warn.add_metric([benchmark["platform"], benchmark["name"], benchmark["schema"]],
                                                  benchmark["warn"])

        yield prom_metric_benchmark_pass
        yield prom_metric_benchmark_fail
        yield prom_metric_benchmark_warn

        first_time_running = False


def scanning_prom_exporter():
    try:
        all_images_with_distro = query_build_images_using_sdk()
        all_images = query_build_images_batch()
        all_runtime_images = query_runtime_images_batch()

    except:
        raise

    for curr_build_image in all_images:
        curr_build_image["running"] = "no"
        curr_build_image["distro"] = "unknown"
        curr_build_image["containers"] = 0
        curr_build_image["cluster"] = ""
        for curr_runtime_image in all_runtime_images:
            if curr_build_image["imageId"] == curr_runtime_image["imageId"]:
                curr_build_image["containers"] = len(curr_runtime_image["containers"])
                curr_build_image["running"] = "yes"
                curr_build_image["cluster"] = curr_runtime_image["cluster"]
        for curr_distro_image in all_images_with_distro:
            if curr_build_image["imageId"] == curr_distro_image["imageId"]:
                curr_build_image["distro"] = curr_distro_image["distro"]

    origin_set = set()
    reg_set = set()
    repo_set = set()
    distro_set = set()

    for image in all_images:
        origin_set.add(image.get("origin"))
        reg_set.add(image.get("reg"))
        repo_set.add(image.get("repo"))
        distro_set.add(image.get("distro"))

    origin_list = list(origin_set)
    reg_list = list(reg_set)
    repo_list = list(repo_set)
    distro_list = list(distro_set)

    final_dict = {}
    for image in all_images:
        for distro in distro_list:
            if image.get("distro") == distro:
                for origin in origin_list:
                    if image.get("origin") == origin:
                        for reg in reg_list:
                            if image.get("reg") == reg:
                                for repo in repo_list:
                                    if image.get("repo") == repo:
                                        for status in status_list:
                                            if image.get("status") == status:
                                                key_string = image.get("distro") + "|" + image.get(
                                                    "origin") + "|" + image.get("reg") + "|" + \
                                                             image.get("repo") + "|" + image.get(
                                                    "status") + "|" + image.get('running') + "|" + \
                                                             str(image.get("containers")) + "|" + image.get("cluster")
                                                if key_string in final_dict:
                                                    final_dict[key_string] = final_dict[key_string] + 1
                                                else:
                                                    final_dict[key_string] = 1
    return final_dict


def query_runtime_images_batch():
    global batch_limit
    offset = 0
    runtime_images = query_runtime_images(offset)
    try:
        while len(runtime_images) == batch_limit + offset:
            offset = offset + batch_limit
            runtime_images = runtime_images + query_runtime_images(offset)
    except:
        raise

    return runtime_images


def query_runtime_images(offset):
    print ("in query_runtime_images")

    auth_string = "Bearer " + secure_api_token
    url = secure_url + "/api/scanning/v1/query/containers"
    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    global batch_limit

    clusters_list = query_cluster_names()
    all_runtime_images = []
    for cluster in clusters_list:
        payload = json.dumps({
            "scope": "kubernetes.cluster.name = \"" + cluster + "\"",
            "skipPolicyEvaluation": False,
            "useCache": True,
            "offset": offset,
            "limit": batch_limit
        })

        try:
            response = requests.request("POST", url, headers=headers_dict, data=payload)
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise

        if response.status_code == 200:
            runtime_images = json.loads(response.text)
            runtime_images = runtime_images["images"]

            print ("total runtime images found - " + str(len(runtime_images)) + " for cluster - " + cluster)

            for image in runtime_images:
                image["cluster"] = cluster

            all_runtime_images = all_runtime_images + runtime_images


        else:
            logging.error("Received an error trying to get the response from: " + url)
            logging.error("Error message: " + response.text)
            raise

    return all_runtime_images


def query_cluster_names():
    print ("in query_cluster_names")

    url = secure_url + "/api/data/entity/metadata"
    auth_string = "Bearer " + secure_api_token

    payload = json.dumps({
        "metrics": [
            "kubernetes.cluster.name"
        ]
    })

    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    try:
        response = requests.request("POST", url, headers=headers_dict, data=payload)
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    if response.status_code == 200:
        clusters = json.loads(response.text)
        clusters = clusters["data"]

        print ("total runtime clusters found - " + str(len(clusters)))

        clusters_list = []
        for cluster in clusters:
            clusters_list.append(cluster["kubernetes.cluster.name"])
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return clusters_list


def query_build_images_batch():
    global batch_limit
    offset = 0
    image_data_list = query_build_images(offset)
    try:
        while len(image_data_list) == batch_limit + offset:
            offset = offset + batch_limit
            image_data_list = image_data_list + query_build_images(offset)
    except:
        raise

    return image_data_list


def query_build_images(offset):

    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/v1/resultsDirect?limit=' + str(batch_limit) + '&offset=' + str(
        offset) + '&sort=desc&sortBy=scanDate&output=json'

    print ("in query_build_images - limit - " + str(batch_limit) + ' -- offset - ' + str(offset))

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        all_build_images = json.loads(response.text)
        all_images_res = all_build_images["results"]

        print ("total build images found - " + str(len(all_build_images)))

        for x in all_images_res:
            image_data_dict["imageId"] = x["imageId"]
            if "origin" in x:
                image_data_dict["origin"] = x["origin"]
            else:
                image_data_dict["origin"] = "NOT FOUND"
            image_data_dict["analysis_status"] = x["analysisStatus"]
            image_data_dict["reg"] = x["registry"]
            image_data_dict["repo"] = x["repository"]
            if "policyStatus" in x:
                if x["policyStatus"] == "STOP":
                    image_data_dict["status"] = "fail"
                else:
                    image_data_dict["status"] = "pass"
            else:
                image_data_dict["status"] = "unknown"

            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list


def query_build_images_using_sdk():
    sdc_client = SdScanningClient(secure_api_token, secure_url)

    print ("in query_build_images_using_sdk")

    try:
        ok, response = sdc_client.list_images()
    except Exception as ex:
        logging.error("Received an exception while invoking the list_images() sdk using secure_url: " + secure_url)
        logging.error(ex)
        raise

    if ok:
        all_images_res = json.loads(json.dumps(response, indent=2))
        image_data_list = []
        image_data_dict = {}

        for x in all_images_res:
            image_data_dict["imageId"] = x["image_detail"][0]["imageId"]
            image_data_dict["distro"] = x["image_content"]["metadata"]["distro"]
            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from list_images sdk: ")
        logging.error("Error message: " + response.text)
        raise

    return image_data_list


def compliance_prom_exporter():
    auth_string = "Bearer " + secure_api_token
    compliance_data_list = []
    compliance_data_dict = {}

    print ("in compliance prom exporter")

    global first_time_running
    global compliance_standards
    if first_time_running:
        url = secure_url + '/api/compliance/v1/standards'
        try:
            response = requests.get(url, headers={"Authorization": auth_string})
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise
        if response.status_code == 200:
            compliance_standards = json.loads(response.text)
        else:
            logging.error("Received an error trying to get the response from: " + url)
            logging.error("Error message: " + response.text)
            raise

    for standard in compliance_standards:
        url = secure_url + '/api/compliance/v1/report?detail=false&standard=' + standard + '&environment=Kubernetes&output=json'
        try:
            response = requests.get(url, headers={"Authorization": auth_string})
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise

        if response.status_code == 200:
            compliance = json.loads(response.text)

            compliance_data_dict["standard"] = standard
            compliance_data_dict["compliance_type"] = "AWS"
            compliance_data_dict["pass"] = str(compliance["pass"])
            compliance_data_dict["fail"] = str(compliance["fail"])
            compliance_data_dict["unchecked"] = str(compliance["unchecked"])
            compliance_data_dict["checked"] = str(compliance["checkedTotal"])

            compliance_data_list.append(compliance_data_dict.copy())
            compliance_data_dict.clear()
        else:
            logging.error("Received an error trying to get the response from: " + url)
            logging.error("Error message: " + response.text)
            raise

    return compliance_data_list


def benchmark_prom_exporter():
    authString = "Bearer " + secure_api_token
    benchmark_data_list = []
    benchmark_data_dict = {}

    print ("in benchmark prom exporter")

    url = secure_url + '/api/benchmarks/v2/tasks'
    try:
        response = requests.get(url, headers={"Authorization": authString})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    if response.status_code == 200:
        benchmark_tasks = json.loads(response.text)

        for benchmark_task in benchmark_tasks:
            if benchmark_task["enabled"]:
                url = secure_url + '/api/benchmarks/v2/tasks/' + str(benchmark_task["id"]) + '/results/' + \
                      benchmark_task["lastRunStartedId"]
                try:
                    response = requests.get(url, headers={"Authorization": authString})
                except Exception as ex:
                    logging.error("Received an exception while invoking the url: " + url)
                    logging.error(ex)
                    raise
                if response.status_code == 200:
                    benchmark = json.loads(response.text)
                    benchmark_data_dict["platform"] = benchmark_task["platform"]
                    benchmark_data_dict["name"] = benchmark_task["name"]
                    benchmark_data_dict["schema"] = benchmark_task["schema"]
                    benchmark_data_dict["enabled"] = benchmark_task["enabled"]
                    benchmark_data_dict["pass"] = str(benchmark["counts"]["resources"]["pass"])
                    benchmark_data_dict["fail"] = str(benchmark["counts"]["resources"]["fail"])
                    benchmark_data_dict["warn"] = str(benchmark["counts"]["resources"]["warn"])

                    benchmark_data_list.append(benchmark_data_dict.copy())
                    benchmark_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        # logging.error("Error message: " + response.text)
        raise

    return benchmark_data_list


'''

def query_runtime_images():
    print ("in query_runtime_images")

    auth_string = "Bearer " + secure_api_token
    url = secure_url + "/api/scanning/v1/query/containers"
    payload = {}

    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    try:
        response = requests.request("POST", url, headers=headers_dict, data=payload)
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    if response.status_code == 200:
        all_runtime_images = json.loads(response.text)
        all_runtime_images = all_runtime_images["images"]

        print ("total runtime images found - " + str(len(all_runtime_images)))

    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return all_runtime_images
'''

if __name__ == '__main__':
    start_http_server(prom_exp_url_port)
    REGISTRY.register(SecureMetricsCollector())
    while True:
        time.sleep(600)
