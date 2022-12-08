

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
customer_name = os.getenv('CUSTOMER_NAME')
query_features_list = os.getenv('QUERY_FEATURES_LIST')


# all - query all features
# if you want to test out a specific product area directly:
test_scanning = "scanning_v1"
test_scanning_v2 = "scanning_v2"
test_compliance = "compliance"
test_benchmark = "benchmark"
test_iam = "iam"

test_area = [test_scanning]
if query_features_list == "all":
    test_area = [test_scanning, test_scanning_v2, test_compliance, test_benchmark, test_iam]
else:
    test_area = query_features_list

first_time_running = True

last_run_date = datetime.now()
last_run_date_str = last_run_date.strftime("%d/%m/%Y %H:%M")

status_list = ["pass", "fail", "unknown"]
posture_compliance_types = ["AWS", "AZURE", "GCP", "WORKLOAD"]

scanning_prom_exp_metrics = {}
all_compliances = []
all_benchmarks = []
all_scanning_v2 = []
iam_policies = []
iam_users = []
iam_roles = []
images_runtime_exploit_hasfix_inuse = []
total_requests = 0



from sdcclient import SdMonitorClient


# sdclient = SdMonitorClient(sdc_token)

# sdclient.get_connected_agents()

class SecureMetricsCollector(object):
    def __init__(self):
        pass

    def collect(self):

        # scanning - new
        prom_metric_scanning_v2_images_critical = GaugeMetricFamily("sysdig_secure_images_scanned_v2_critical",
                                                                    'critical vul using new scanning engine',
                                                                    labels=['sysdig_secure_image_id',
                                                                            'sysdig_secure_image_reg_name',
                                                                            'sysdig_secure_image_repo_name',
                                                                            'sysdig_secure_image_pull_string',
                                                                            'sysdig_secure_image_status',
                                                                            'sysdig_secure_image_running',
                                                                            'sysdig_secure_image_name',
                                                                            'sysdig_secure_asset_type',
                                                                            'sysdig_secure_cluster_name',
                                                                            'sysdig_secure_namespace_name',
                                                                            'sysdig_secure_workload_name',
                                                                            'sysdig_secure_workload_type',
                                                                            'sysdig_secure_customer_name'
                                                                            ])

        prom_metric_scanning_v2_images_high = GaugeMetricFamily("sysdig_secure_images_scanned_v2_high",
                                                                'high vul using new scanning engine',
                                                                labels=['sysdig_secure_image_id',
                                                                        'sysdig_secure_image_reg_name',
                                                                        'sysdig_secure_image_repo_name',
                                                                        'sysdig_secure_image_pull_string',
                                                                        'sysdig_secure_image_status',
                                                                        'sysdig_secure_image_running',
                                                                        'sysdig_secure_image_name',
                                                                        'sysdig_secure_asset_type',
                                                                        'sysdig_secure_cluster_name',
                                                                        'sysdig_secure_namespace_name',
                                                                        'sysdig_secure_workload_name',
                                                                        'sysdig_secure_workload_type',
                                                                        'sysdig_secure_customer_name'
                                                                        ])

        prom_metric_scanning_v2_images_medium = GaugeMetricFamily("sysdig_secure_images_scanned_v2_medium",
                                                                  'critical vul using new scanning engine',
                                                                  labels=['sysdig_secure_image_id',
                                                                          'sysdig_secure_image_reg_name',
                                                                          'sysdig_secure_image_repo_name',
                                                                          'sysdig_secure_image_pull_string',
                                                                          'sysdig_secure_image_status',
                                                                          'sysdig_secure_image_running',
                                                                          'sysdig_secure_image_name',
                                                                          'sysdig_secure_asset_type',
                                                                          'sysdig_secure_cluster_name',
                                                                          'sysdig_secure_namespace_name',
                                                                          'sysdig_secure_workload_name',
                                                                          'sysdig_secure_workload_type',
                                                                          'sysdig_secure_customer_name'
                                                                          ])

        prom_metric_scanning_v2_images_low = GaugeMetricFamily("sysdig_secure_images_scanned_v2_low",
                                                               'critical vul using new scanning engine',
                                                               labels=['sysdig_secure_image_id',
                                                                       'sysdig_secure_image_reg_name',
                                                                       'sysdig_secure_image_repo_name',
                                                                       'sysdig_secure_image_pull_string',
                                                                       'sysdig_secure_image_status',
                                                                       'sysdig_secure_image_running',
                                                                       'sysdig_secure_image_name',
                                                                       'sysdig_secure_asset_type',
                                                                       'sysdig_secure_cluster_name',
                                                                       'sysdig_secure_namespace_name',
                                                                       'sysdig_secure_workload_name',
                                                                       'sysdig_secure_workload_type',
                                                                       'sysdig_secure_customer_name'
                                                                       ])

        prom_metric_scanning_v2_images_in_use_critical = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_in_use_critical",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_in_use_high = GaugeMetricFamily("sysdig_secure_images_scanned_v2_in_use_high",
                                                                       'critical vul using new scanning engine',
                                                                       labels=['sysdig_secure_image_id',
                                                                               'sysdig_secure_image_reg_name',
                                                                               'sysdig_secure_image_repo_name',
                                                                               'sysdig_secure_image_pull_string',
                                                                               'sysdig_secure_image_status',
                                                                               'sysdig_secure_image_running',
                                                                               'sysdig_secure_image_name',
                                                                               'sysdig_secure_asset_type',
                                                                               'sysdig_secure_cluster_name',
                                                                               'sysdig_secure_namespace_name',
                                                                               'sysdig_secure_workload_name',
                                                                               'sysdig_secure_workload_type',
                                                                               'sysdig_secure_customer_name'
                                                                               ])

        prom_metric_scanning_v2_images_in_use_medium = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_in_use_medium",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_in_use_low = GaugeMetricFamily("sysdig_secure_images_scanned_v2_in_use_low",
                                                                      'critical vul using new scanning engine',
                                                                      labels=['sysdig_secure_image_id',
                                                                              'sysdig_secure_image_reg_name',
                                                                              'sysdig_secure_image_repo_name',
                                                                              'sysdig_secure_image_pull_string',
                                                                              'sysdig_secure_image_status',
                                                                              'sysdig_secure_image_running',
                                                                              'sysdig_secure_image_name',
                                                                              'sysdig_secure_asset_type',
                                                                              'sysdig_secure_cluster_name',
                                                                              'sysdig_secure_namespace_name',
                                                                              'sysdig_secure_workload_name',
                                                                              'sysdig_secure_workload_type',
                                                                              'sysdig_secure_customer_name'
                                                                              ])

        prom_metric_scanning_v2_images_exploit_count = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_exploit_count",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_exploit_fix_inuse_count = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_exploit_fix_inuse_count",
            'critical vul using new scanning engine that has exploit, fix & inuse',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_images_v2 = GaugeMetricFamily("sysdig_secure_images_scanned_v2",
                                                        'All the images detected in your cluster with new scan engine.',
                                                        labels=['sysdig_secure_image_scan_origin',
                                                                'sysdig_secure_image_reg_name',
                                                                'sysdig_secure_image_repo_name',
                                                                'sysdig_secure_image_pull_string',
                                                                'sysdig_secure_image_status',
                                                                'sysdig_secure_image_running',
                                                                'sysdig_secure_image_name',
                                                                'sysdig_secure_asset_type',
                                                                'sysdig_secure_cluster_name',
                                                                'sysdig_secure_namespace_name',
                                                                'sysdig_secure_workload_name',
                                                                'sysdig_secure_workload_type',
                                                                'sysdig_secure_node_name',
                                                                'sysdig_secure_critical_vuln',
                                                                'sysdig_secure_high_vuln',
                                                                'sysdig_secure_medium_vuln',
                                                                'sysdig_secure_low_vuln',
                                                                'sysdig_secure_in_use_critical_vuln',
                                                                'sysdig_secure_in_use_high_vuln',
                                                                'sysdig_secure_in_use_medium_vuln',
                                                                'sysdig_secure_in_use_low_vuln',
                                                                'sysdig_secure_exploit_count',
                                                                'sysdig_secure_customer_name'
                                                                ])

        # Scanning - old
        prom_metric_scanning_images = GaugeMetricFamily("sysdig_secure_images_scanned",
                                                        'All the images detected in your cluster with scan result.',
                                                        labels=['sysdig_secure_image_distro',
                                                                'sysdig_secure_image_scan_origin',
                                                                'sysdig_secure_image_reg_name',
                                                                'sysdig_secure_image_repo_name',
                                                                'sysdig_secure_image_status',
                                                                'sysdig_secure_image_running',
                                                                'sysdig_secure_containers',
                                                                'sysdig_secure_cluster',
                                                                'sysdig_secure_customer_name'
                                                                ])

        # Compliance

        prom_metric_compliance_pass = GaugeMetricFamily("sysdig_secure_compliance_pass",
                                                        'How many controls passed against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_fail = GaugeMetricFamily("sysdig_secure_compliance_fail",
                                                        'How many controls failed against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_warn = GaugeMetricFamily("sysdig_secure_compliance_warn",
                                                        'How many controls warned against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_total = GaugeMetricFamily("sysdig_secure_compliance_total",
                                                         'How many total controls for the compliance.',
                                                         labels=['sysdig_secure_compliance_name',
                                                                 'sysdig_secure_compliance_type',
                                                                 'sysdig_secure_compliance_schema',
                                                                 'sysdig_secure_compliance_framework',
                                                                 'sysdig_secure_compliance_version',
                                                                 'sysdig_secure_compliance_platform',
                                                                 'sysdig_secure_compliance_family',
                                                                 'sysdig_secure_customer_name'])

        prom_metric_compliance_pass_perc = GaugeMetricFamily("sysdig_secure_compliance_pass_perc",
                                                             'How many % controls passed against the compliance.',
                                                             labels=['sysdig_secure_compliance_name',
                                                                     'sysdig_secure_compliance_type',
                                                                     'sysdig_secure_compliance_schema',
                                                                     'sysdig_secure_compliance_framework',
                                                                     'sysdig_secure_compliance_version',
                                                                     'sysdig_secure_compliance_platform',
                                                                     'sysdig_secure_compliance_family',
                                                                     'sysdig_secure_customer_name'])

        # prom_metric_compliance_pass = GaugeMetricFamily("sysdig_secure_compliance_pass",
        #                                                 'How many controls passed against the compliance.',
        #                                                 labels=['sysdig_secure_compliance_standard',
        #                                                         'sysdig_secure_compliance',
        #                                                         'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_fail = GaugeMetricFamily("sysdig_secure_compliance_fail",
        #                                                 'How many controls failed against the compliance.',
        #                                                 labels=['sysdig_secure_compliance_standard',
        #                                                         'sysdig_secure_compliance',
        #                                                         'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_checked = GaugeMetricFamily("sysdig_secure_compliance_checked",
        #                                                    'How many controls checked against the compliance.',
        #                                                    labels=['sysdig_secure_compliance_standard',
        #                                                            'sysdig_secure_compliance',
        #                                                            'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_unchecked = GaugeMetricFamily("sysdig_secure_compliance_unchecked",
        #                                                      'How many controls unchecked against the compliance.',
        #                                                      labels=['sysdig_secure_compliance_standard',
        #                                                              'sysdig_secure_compliance',
        #                                                              'sysdig_secure_compliance_type'])

        # Benchmarks
        prom_metric_benchmark_resource_pass = GaugeMetricFamily("sysdig_secure_benchmark_resources_pass",
                                                                'How many resources passed against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_resource_fail = GaugeMetricFamily("sysdig_secure_benchmark_resources_fail",
                                                                'How many resources failed against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_resource_warn = GaugeMetricFamily("sysdig_secure_benchmark_resources_warn",
                                                                'How many resources warn against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_pass = GaugeMetricFamily("sysdig_secure_benchmark_control_pass",
                                                               'How many controls passed against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_fail = GaugeMetricFamily("sysdig_secure_benchmark_control_fail",
                                                               'How many controls failed against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_warn = GaugeMetricFamily("sysdig_secure_benchmark_control_warn",
                                                               'How many controls warn against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        # iam
        prom_metric_iam_policy = GaugeMetricFamily("sysdig_secure_iam_policy",
                                                     'IAM policies',
                                                     labels=['sysdig_secure_iam_policy_name',
                                                             'sysdig_secure_iam_actors_total',
                                                             'sysdig_secure_iam_permissions_given_total',
                                                             'sysdig_secure_iam_permissions_unused_total',
                                                             'sysdig_secure_iam_risk_category',
                                                             'sysdig_secure_iam_risky_permissions_total',
                                                             'sysdig_secure_iam_risk_score',
                                                             'sysdig_secure_iam_policy_type',
                                                             'sysdig_secure_iam_excessive_risk_category',
                                                             'sysdig_secure_iam_execssive_risky_permissions_total',
                                                             'sysdig_secure_iam_excessive_risk_score',
                                                             'sysdig_secure_customer_name'
                                                             ])

        prom_metric_iam_policy_perms_given_total = GaugeMetricFamily("sysdig_secure_iam_policy_perms_given_total",
                                                   'IAM policies permissions given total',
                                                   labels=['sysdig_secure_iam_policy_name',
                                                           'sysdig_secure_iam_actors_total',
                                                           'sysdig_secure_iam_risk_category',
                                                           'sysdig_secure_iam_policy_type',
                                                           'sysdig_secure_customer_name'
                                                           ])

        prom_metric_iam_policy_perms_unused_total = GaugeMetricFamily("sysdig_secure_iam_policy_perms_unused_total",
                                                                     'IAM policies permissions unused total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_risky_perms_total = GaugeMetricFamily("sysdig_secure_iam_policy_risky_perms_total",
                                                                     'IAM policies risky permissions total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_risk_score = GaugeMetricFamily("sysdig_secure_iam_policy_risk_score",
                                                                     'IAM policies risk score',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_excessive_risky_perms_total = GaugeMetricFamily("sysdig_secure_iam_policy_excessive_risky_perms_total",
                                                                     'IAM policies excessive risky permissions total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_excessive_risk_score = GaugeMetricFamily("sysdig_secure_iam_policy_excessive_risk_score",
                                                              'IAM policies excessive risk score',
                                                              labels=['sysdig_secure_iam_policy_name',
                                                                      'sysdig_secure_iam_actors_total',
                                                                      'sysdig_secure_iam_risk_category',
                                                                      'sysdig_secure_iam_policy_type',
                                                                      'sysdig_secure_customer_name'
                                                                      ])

        prom_metric_iam_user = GaugeMetricFamily("sysdig_secure_iam_user",
                                                     'IAM users',
                                                     labels=['sysdig_secure_iam_user_name',
                                                             'sysdig_secure_iam_user_policies_total',
                                                             'sysdig_secure_iam_permissions_given_total',
                                                             'sysdig_secure_iam_permissions_effective_total',
                                                             'sysdig_secure_iam_permissions_unused_total',
                                                             'sysdig_secure_iam_permissions_used_total',
                                                             'sysdig_secure_iam_risk_category',
                                                             'sysdig_secure_iam_risky_permissions_total',
                                                             'sysdig_secure_iam_risk_score',
                                                             'sysdig_secure_iam_excessive_risk_category',
                                                             'sysdig_secure_iam_execssive_risky_permissions_total',
                                                             'sysdig_secure_iam_excessive_risk_score',
                                                             'sysdig_secure_iam_user_risk_admin',
                                                             'sysdig_secure_iam_user_risk_inactive',
                                                             'sysdig_secure_iam_user_risk_no_mfa',
                                                             'sysdig_secure_iam_user_risk_key1_not_rotated',
                                                             'sysdig_secure_iam_user_risk_key2_not_rotated',
                                                             'sysdig_secure_iam_user_risk_multiple_keys',
                                                             'sysdig_secure_customer_name'
                                                             ])

        prom_metric_iam_user_permissions_given_total = GaugeMetricFamily("sysdig_secure_iam_user_permissions_given_total",
                                                 'IAM users permissions given',
                                                 labels=['sysdig_secure_iam_user_name',
                                                         'sysdig_secure_iam_user_policies_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_user_risk_admin',
                                                         'sysdig_secure_iam_user_risk_inactive',
                                                         'sysdig_secure_iam_user_risk_no_mfa',
                                                         'sysdig_secure_iam_user_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_user_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_user_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_user_permissions_unused_total = GaugeMetricFamily(
            "sysdig_secure_iam_user_permissions_unused_total",
            'IAM users permissions unused',
            labels=['sysdig_secure_iam_user_name',
                    'sysdig_secure_iam_user_policies_total',
                    'sysdig_secure_iam_risk_category',
                    'sysdig_secure_iam_excessive_risk_category',
                    'sysdig_secure_iam_user_risk_admin',
                    'sysdig_secure_iam_user_risk_inactive',
                    'sysdig_secure_iam_user_risk_no_mfa',
                    'sysdig_secure_iam_user_risk_key1_not_rotated',
                    'sysdig_secure_iam_user_risk_key2_not_rotated',
                    'sysdig_secure_iam_user_risk_multiple_keys',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_iam_role = GaugeMetricFamily("sysdig_secure_iam_role",
                                                 'IAM roles',
                                                 labels=['sysdig_secure_iam_role_name',
                                                         'sysdig_secure_iam_role_policies_total',
                                                         'sysdig_secure_iam_permissions_given_total',
                                                         'sysdig_secure_iam_permissions_effective_total',
                                                         'sysdig_secure_iam_permissions_unused_total',
                                                         'sysdig_secure_iam_permissions_used_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_risky_permissions_total',
                                                         'sysdig_secure_iam_risk_score',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_execssive_risky_permissions_total',
                                                         'sysdig_secure_iam_excessive_risk_score',
                                                         'sysdig_secure_iam_role_risk_admin',
                                                         'sysdig_secure_iam_role_risk_inactive',
                                                         'sysdig_secure_iam_role_risk_no_mfa',
                                                         'sysdig_secure_iam_role_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_role_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_role_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_role_permissions_given_total = GaugeMetricFamily("sysdig_secure_iam_role_permissions_given_total",
                                                 'IAM roles permissions total',
                                                 labels=['sysdig_secure_iam_role_name',
                                                         'sysdig_secure_iam_role_policies_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_role_risk_admin',
                                                         'sysdig_secure_iam_role_risk_inactive',
                                                         'sysdig_secure_iam_role_risk_no_mfa',
                                                         'sysdig_secure_iam_role_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_role_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_role_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_role_permissions_unused_total = GaugeMetricFamily(
            "sysdig_secure_iam_role_permissions_unused_total",
            'IAM roles permissions unused',
            labels=['sysdig_secure_iam_role_name',
                    'sysdig_secure_iam_role_policies_total',
                    'sysdig_secure_iam_risk_category',
                    'sysdig_secure_iam_excessive_risk_category',
                    'sysdig_secure_iam_role_risk_admin',
                    'sysdig_secure_iam_role_risk_inactive',
                    'sysdig_secure_iam_role_risk_no_mfa',
                    'sysdig_secure_iam_role_risk_key1_not_rotated',
                    'sysdig_secure_iam_role_risk_key2_not_rotated',
                    'sysdig_secure_iam_role_risk_multiple_keys',
                    'sysdig_secure_customer_name'
                    ])

        curr_date = datetime.now()
        curr_date_str = curr_date.strftime("%d/%m/%Y %H:%M")

        global total_requests

        global last_run_date
        global last_run_date_str
        global first_time_running

        global scanning_prom_exp_metrics
        global all_compliances
        global all_benchmarks
        global all_scanning_v2
        global iam_policies
        global iam_users
        global iam_roles
        global images_runtime_exploit_hasfix_inuse
        global customer_name

        next_run_date = last_run_date + timedelta(minutes=scheduled_run_minutes)
        next_run_date_str = next_run_date.strftime("%d/%m/%Y %H:%M")

        if first_time_running:
            print_info()

        print("last_run_date_str - " + last_run_date_str)
        print("curr_date_str - " + curr_date_str)
        print("next_run_date_str - " + next_run_date_str)

        if next_run_date > curr_date and not first_time_running:
            print("Skipping querying......")
            print("Returning metrics from memory ")

            if test_scanning_v2 in test_area:
                print("Scanning v2 from memory - " + str(len(all_scanning_v2)))
                for scanning in all_scanning_v2:
                    prom_metric_scanning_v2_images_critical.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["critical"]
                    )

                    prom_metric_scanning_v2_images_high.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["high"]
                    )

                    prom_metric_scanning_v2_images_medium.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["medium"]
                    )

                    prom_metric_scanning_v2_images_low.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["low"]
                    )

                    # in use
                    prom_metric_scanning_v2_images_in_use_critical.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_critical"]
                    )

                    prom_metric_scanning_v2_images_in_use_high.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_high"]
                    )

                    prom_metric_scanning_v2_images_in_use_medium.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_medium"]
                    )

                    prom_metric_scanning_v2_images_in_use_low.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_low"]
                    )

                    prom_metric_scanning_v2_images_exploit_count.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["exploitCount"]
                    )

                    prom_metric_scanning_images_v2.add_metric(
                        [scanning["origin"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"],  scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], scanning["node_name"], str(scanning["critical"]), str(scanning["high"]),
                         str(scanning["medium"]), str(scanning["low"]), str(scanning["in_use_critical"]), str(scanning["in_use_high"]),
                         str(scanning["in_use_medium"]), str(scanning["in_use_low"]), str(scanning["exploitCount"]), customer_name],
                        len(all_scanning_v2)
                    )

                for scanning in images_runtime_exploit_hasfix_inuse:
                    prom_metric_scanning_v2_images_exploit_fix_inuse_count.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["fix_exploitable_running"]
                    )

                yield prom_metric_scanning_v2_images_critical
                yield prom_metric_scanning_v2_images_high
                yield prom_metric_scanning_v2_images_medium
                yield prom_metric_scanning_v2_images_low
                yield prom_metric_scanning_v2_images_in_use_critical
                yield prom_metric_scanning_v2_images_in_use_high
                yield prom_metric_scanning_v2_images_in_use_medium
                yield prom_metric_scanning_v2_images_in_use_low
                yield prom_metric_scanning_v2_images_exploit_count
                yield prom_metric_scanning_images_v2
                yield prom_metric_scanning_v2_images_exploit_fix_inuse_count

            if test_scanning in test_area:
                print("Scanning v1 from memory - " + str(len(scanning_prom_exp_metrics)))
                for x in scanning_prom_exp_metrics.keys():
                    temp_string = x.split("|")
                    prom_metric_scanning_images.add_metric(
                        [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                         temp_string[6], temp_string[7], customer_name],
                        scanning_prom_exp_metrics[x])
                yield prom_metric_scanning_images

            if test_compliance in test_area:
                print("Compliance from memory - " + str(len(all_compliances)))
                for compliance in all_compliances:
                    prom_metric_compliance_pass.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_pass"])

                    prom_metric_compliance_fail.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_fail"])

                    prom_metric_compliance_warn.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_warn"])

                    prom_metric_compliance_pass_perc.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_pass_percent"])

                    prom_metric_compliance_total.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_total"])

                    # prom_metric_compliance_pass.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                        compliance["pass"])
                    # prom_metric_compliance_fail.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                        compliance["fail"])
                    # prom_metric_compliance_checked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                           compliance["checked"])
                    # prom_metric_compliance_unchecked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                             compliance["unchecked"])

                yield prom_metric_compliance_pass
                yield prom_metric_compliance_fail
                yield prom_metric_compliance_warn
                # yield prom_metric_compliance_total
                yield prom_metric_compliance_pass_perc

            if test_benchmark in test_area:
                print("Benchmarks from memory - " + str(len(all_benchmarks)))
                for benchmark in all_benchmarks:
                    prom_metric_benchmark_resource_pass.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_pass"])
                    prom_metric_benchmark_resource_fail.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_fail"])
                    prom_metric_benchmark_resource_warn.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_warn"])

                    prom_metric_benchmark_control_pass.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_pass"])
                    prom_metric_benchmark_control_fail.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_fail"])
                    prom_metric_benchmark_control_warn.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_warn"])

                yield prom_metric_benchmark_resource_pass
                yield prom_metric_benchmark_resource_fail
                yield prom_metric_benchmark_resource_warn

                yield prom_metric_benchmark_control_pass
                yield prom_metric_benchmark_control_fail
                yield prom_metric_benchmark_control_warn

            if test_iam in test_area:
                print("iam policies from memory - " + str(len(iam_policies)))
                for policy in iam_policies:
                    prom_metric_iam_policy.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]), str(policy["numPermissionsGiven"]), str(policy["numPermissionsUnused"]),
                         policy["riskCategory"], str(policy["riskyPermissions"]), str(policy["riskScore"]), policy["policyType"], policy["excessiveRiskCategory"],
                         str(policy["excessiveRiskyPermissions"]), str(policy["excessiveRiskScore"]), policy["customerName"]],
                        len(iam_policies)
                    )

                    prom_metric_iam_policy_perms_given_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["numPermissionsGiven"]
                    )

                    prom_metric_iam_policy_perms_unused_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["numPermissionsUnused"]
                    )

                    prom_metric_iam_policy_risky_perms_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["riskyPermissions"]
                    )

                    prom_metric_iam_policy_risk_score.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["riskScore"]
                    )

                    prom_metric_iam_policy_excessive_risky_perms_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["excessiveRiskyPermissions"]
                    )

                    prom_metric_iam_policy_excessive_risk_score.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["excessiveRiskScore"]
                    )

                print("iam users from memory - " + str(len(iam_users)))
                for user in iam_users:
                    prom_metric_iam_user.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), str(user["numPermissionsGiven"]),
                         str(user["effectivePermissionsCount"]), str(user["numPermissionsUnused"]),
                         str(user["numPermissionsUsed"]),
                         user["riskCategory"], str(user["riskyPermissions"]), str(user["riskScore"]),
                         user["excessiveRiskCategory"],
                         str(user["excessiveRiskyPermissions"]), str(user["excessiveRiskScore"]),
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        len(iam_users)
                    )

                    prom_metric_iam_user_permissions_given_total.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), user["riskCategory"],
                         user["excessiveRiskCategory"],
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        user["numPermissionsGiven"]
                    )

                    prom_metric_iam_user_permissions_unused_total.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), user["riskCategory"],
                         user["excessiveRiskCategory"],
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        user["numPermissionsUnused"]
                    )

                print("iam roles from memory - " + str(len(iam_roles)))
                for role in iam_roles:
                    prom_metric_iam_role.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), str(role["numPermissionsGiven"]),
                         str(role["effectivePermissionsCount"]), str(role["numPermissionsUnused"]),
                         str(role["numPermissionsUsed"]),
                         role["riskCategory"], str(role["riskyPermissions"]), str(role["riskScore"]),
                         role["excessiveRiskCategory"],
                         str(role["excessiveRiskyPermissions"]), str(role["excessiveRiskScore"]),
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        len(iam_roles)
                    )

                    prom_metric_iam_role_permissions_given_total.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), role["riskCategory"],
                         role["excessiveRiskCategory"],
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        role["numPermissionsGiven"]
                    )

                    prom_metric_iam_role_permissions_unused_total.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), role["riskCategory"],
                         role["excessiveRiskCategory"],
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        role["numPermissionsUnused"]
                    )

                yield prom_metric_iam_policy
                yield prom_metric_iam_policy_perms_given_total
                yield prom_metric_iam_policy_perms_unused_total
                yield prom_metric_iam_policy_risky_perms_total
                yield prom_metric_iam_policy_risk_score
                yield prom_metric_iam_policy_excessive_risky_perms_total
                yield prom_metric_iam_policy_excessive_risk_score

                yield prom_metric_iam_user
                yield prom_metric_iam_user_permissions_given_total
                yield prom_metric_iam_user_permissions_unused_total

                yield prom_metric_iam_role
                yield prom_metric_iam_role_permissions_given_total
                yield prom_metric_iam_role_permissions_unused_total

                print("yielded iam prom exporter")

            return



        # **********************************************************************

        # Using API
        # ***********************************************************************




        print("still running... waiting for the first iteration to complete. Skipping querying...")

        print("Querying metrics from Sysdig Secure Backend using APIs....")
        # ------------------------------------------------------------------------------

        last_run_date = curr_date
        next_run_date = curr_date + timedelta(minutes=scheduled_run_minutes)

        # scanning - new
        if test_scanning_v2 in test_area:
            try:
                all_scanning_v2, images_runtime_exploit_hasfix_inuse = scanning_v2_prom_exporter()
            except Exception as ex:
                logging.error(ex)
                return

            # print("scanning_v2_prom_exp_metrics count - " + str(len(all_scanning_v2)))

            total_requests += 1

            for scanning in all_scanning_v2:
                prom_metric_scanning_v2_images_critical.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["critical"]
                )

                prom_metric_scanning_v2_images_high.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["high"]
                )

                prom_metric_scanning_v2_images_medium.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["medium"]
                )

                prom_metric_scanning_v2_images_low.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["low"]
                )

                # in use
                prom_metric_scanning_v2_images_in_use_critical.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_critical"]
                )

                prom_metric_scanning_v2_images_in_use_high.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_high"]
                )

                prom_metric_scanning_v2_images_in_use_medium.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_medium"]
                )

                prom_metric_scanning_v2_images_in_use_low.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_low"]
                )

                prom_metric_scanning_v2_images_exploit_count.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["exploitCount"]
                )

                prom_metric_scanning_images_v2.add_metric(
                    [scanning["origin"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], scanning["node_name"], str(scanning["critical"]), str(scanning["high"]),
                     str(scanning["medium"]), str(scanning["low"]), str(scanning["in_use_critical"]),
                     str(scanning["in_use_high"]),
                     str(scanning["in_use_medium"]), str(scanning["in_use_low"]), str(scanning["exploitCount"]),
                     customer_name],
                    len(all_scanning_v2)
                )

            for scanning in images_runtime_exploit_hasfix_inuse:
                prom_metric_scanning_v2_images_exploit_fix_inuse_count.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["fix_exploitable_running"]
                )


            yield prom_metric_scanning_v2_images_critical
            yield prom_metric_scanning_v2_images_high
            yield prom_metric_scanning_v2_images_medium
            yield prom_metric_scanning_v2_images_low
            yield prom_metric_scanning_v2_images_in_use_critical
            yield prom_metric_scanning_v2_images_in_use_high
            yield prom_metric_scanning_v2_images_in_use_medium
            yield prom_metric_scanning_v2_images_in_use_low
            yield prom_metric_scanning_v2_images_exploit_count
            yield prom_metric_scanning_images_v2
            yield prom_metric_scanning_v2_images_exploit_fix_inuse_count

            print("yielded scanning_v2 prom exporter")

        # scanning - old
        if test_scanning in test_area:

            try:
                scanning_prom_exp_metrics = scanning_prom_exporter()
            except Exception as ex:
                logging.error(ex)
                return

            print("scanning_prom_exp_metrics count - " + str(len(scanning_prom_exp_metrics)))

            total_requests += 1

            for x in scanning_prom_exp_metrics.keys():
                temp_string = x.split("|")
                prom_metric_scanning_images.add_metric(
                    [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                     temp_string[6], temp_string[7], customer_name],
                    scanning_prom_exp_metrics[x])
            yield prom_metric_scanning_images

            print("yielded scanning prom exporter")

        # compliance
        if test_compliance in test_area:

            all_compliances = compliance_prom_exporter()

            print("all compliance count - " + str(len(all_compliances)))

            for compliance in all_compliances:
                prom_metric_compliance_pass.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_pass"])

                prom_metric_compliance_fail.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_fail"])

                prom_metric_compliance_warn.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_warn"])

                prom_metric_compliance_pass_perc.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_pass_percent"])

                prom_metric_compliance_total.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_total"])

                # prom_metric_compliance_pass.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                        compliance["pass"])
                # prom_metric_compliance_fail.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                        compliance["fail"])
                # prom_metric_compliance_checked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                           compliance["checked"])
                # prom_metric_compliance_unchecked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                             compliance["unchecked"])

            yield prom_metric_compliance_pass
            yield prom_metric_compliance_fail
            yield prom_metric_compliance_warn
            # yield prom_metric_compliance_total
            yield prom_metric_compliance_pass_perc

            print("yielded compliance prom exporter")

        # Benchmarks

        if test_benchmark in test_area:
            all_benchmarks = benchmark_prom_exporter()

            print("all benchmark count - " + str(len(all_benchmarks)))

            # adding control pass, clustername, node name
            # update the code....

            for benchmark in all_benchmarks:
                prom_metric_benchmark_resource_pass.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_pass"])
                prom_metric_benchmark_resource_fail.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_fail"])
                prom_metric_benchmark_resource_warn.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_warn"])

                prom_metric_benchmark_control_pass.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_pass"])
                prom_metric_benchmark_control_fail.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_fail"])
                prom_metric_benchmark_control_warn.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_warn"])

            yield prom_metric_benchmark_resource_pass
            yield prom_metric_benchmark_resource_fail
            yield prom_metric_benchmark_resource_warn

            yield prom_metric_benchmark_control_pass
            yield prom_metric_benchmark_control_fail
            yield prom_metric_benchmark_control_warn

            print("yielded benchmark prom exporter")


        # iam
        if test_iam in test_area:
            try:
                iam_policies, iam_users, iam_roles = iam_prom_exporter()

            except Exception as ex:
                logging.error(ex)
                return

            print("iam policies count - " + str(len(iam_policies)))
            print("iam users count - " + str(len(iam_users)))
            print("iam roles count - " + str(len(iam_roles)))

            total_requests += 1

            for policy in iam_policies:
                prom_metric_iam_policy.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]), str(policy["numPermissionsGiven"]),
                     str(policy["numPermissionsUnused"]),
                     policy["riskCategory"], str(policy["riskyPermissions"]), str(policy["riskScore"]),
                     policy["policyType"], policy["excessiveRiskCategory"],
                     str(policy["excessiveRiskyPermissions"]), str(policy["excessiveRiskScore"]),
                     policy["customerName"]],
                    len(iam_policies)
                )

                prom_metric_iam_policy_perms_given_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["numPermissionsGiven"]
                )

                prom_metric_iam_policy_perms_unused_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["numPermissionsUnused"]
                )

                prom_metric_iam_policy_risky_perms_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["riskyPermissions"]
                )

                prom_metric_iam_policy_risk_score.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["riskScore"]
                )

                prom_metric_iam_policy_excessive_risky_perms_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["excessiveRiskyPermissions"]
                )

                prom_metric_iam_policy_excessive_risk_score.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["excessiveRiskScore"]
                )

            for user in iam_users:
                prom_metric_iam_user.add_metric(
                    [user["actorName"], str(user["policiesTotal"]), str(user["numPermissionsGiven"]),
                     str(user["effectivePermissionsCount"]), str(user["numPermissionsUnused"]), str(user["numPermissionsUsed"]),
                     user["riskCategory"], str(user["riskyPermissions"]), str(user["riskScore"]),
                     user["excessiveRiskCategory"],
                     str(user["excessiveRiskyPermissions"]), str(user["excessiveRiskScore"]),
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    len(iam_users)
                )

                prom_metric_iam_user_permissions_given_total.add_metric(
                    [user["actorName"], str(user["policiesTotal"]),  user["riskCategory"], user["excessiveRiskCategory"],
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    user["numPermissionsGiven"]
                )

                prom_metric_iam_user_permissions_unused_total.add_metric(
                    [user["actorName"], str(user["policiesTotal"]), user["riskCategory"], user["excessiveRiskCategory"],
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    user["numPermissionsUnused"]
                )

            for role in iam_roles:
                prom_metric_iam_role.add_metric(
                    [role["actorName"], str(role["policiesTotal"]), str(role["numPermissionsGiven"]),
                     str(role["effectivePermissionsCount"]), str(role["numPermissionsUnused"]), str(role["numPermissionsUsed"]),
                     role["riskCategory"], str(role["riskyPermissions"]), str(role["riskScore"]),
                     role["excessiveRiskCategory"],
                     str(role["excessiveRiskyPermissions"]), str(role["excessiveRiskScore"]),
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    len(iam_roles)
                )

                prom_metric_iam_role_permissions_given_total.add_metric(
                    [role["actorName"], str(role["policiesTotal"]),  role["riskCategory"], role["excessiveRiskCategory"],
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    role["numPermissionsGiven"]
                )

                prom_metric_iam_role_permissions_unused_total.add_metric(
                    [role["actorName"], str(role["policiesTotal"]), role["riskCategory"], role["excessiveRiskCategory"],
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    role["numPermissionsUnused"]
                )

            yield prom_metric_iam_policy
            yield prom_metric_iam_policy_perms_given_total
            yield prom_metric_iam_policy_perms_unused_total
            yield prom_metric_iam_policy_risky_perms_total
            yield prom_metric_iam_policy_risk_score
            yield prom_metric_iam_policy_excessive_risky_perms_total
            yield prom_metric_iam_policy_excessive_risk_score

            yield prom_metric_iam_user
            yield prom_metric_iam_user_permissions_given_total
            yield prom_metric_iam_user_permissions_unused_total

            yield prom_metric_iam_role
            yield prom_metric_iam_role_permissions_given_total
            yield prom_metric_iam_role_permissions_unused_total

            print("yielded iam prom exporter")

        first_time_running = False


def scanning_v2_prom_exporter():
    try:

        # commenting out pipeline for testing purpose....
        images_pipeline = []
        #images_pipeline = query_scanning_v2_pipeline_images_batch()

        images_runtime = query_scanning_v2_runtime_images_batch()

        print("# of images in Pipeline (Scanning v2) - " + str(len(images_pipeline)))
        print("# of images in Runtime (Scanning v2) - " + str(len(images_runtime)))

        images_scanning_v2 = images_pipeline + images_runtime

        images_runtime_exploit_hasfix_inuse = query_scanning_v2_image_details(images_runtime)

    except:
        raise

    return images_scanning_v2, images_runtime_exploit_hasfix_inuse


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

        # fixing None type - if None found, replace it with unknown
        if image["distro"] is None:
            image["distro"] = "unknown"
        if image["origin"] is None:
            image["origin"] = "unknown"
        if image["reg"] is None:
            image["reg"] = "unknown"
        if image["repo"] is None:
            image["repo"] = "unknown"

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
    auth_string = "Bearer " + secure_api_token
    url = secure_url + "/api/scanning/v1/query/containers"
    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    global batch_limit

    clusters_list = query_cluster_names()
    all_runtime_images = []
    for cluster in clusters_list:
        if cluster != "non-k8s":
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

                print("total runtime images found - " + str(len(runtime_images)) + " for cluster - " + cluster)

                for image in runtime_images:
                    image["cluster"] = cluster

                all_runtime_images = all_runtime_images + runtime_images


            else:
                logging.error("Received an error trying to get the response from: " + url)
                logging.error("Error message: " + response.text)
                raise

    return all_runtime_images


def query_cluster_names():
    print("in query_cluster_names")

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

        print("total runtime clusters found - " + str(len(clusters)))

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

    print("in query_build_images - limit - " + str(batch_limit) + ' -- offset - ' + str(offset))

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


def query_scanning_v2_pipeline_images_batch():
    image_data_list, next_cursor = query_scanning_v2_pipeline_images("")
    try:
        while next_cursor is not None:
            image_data_list_temp, next_cursor = query_scanning_v2_pipeline_images(next_cursor)
            image_data_list = image_data_list + image_data_list_temp
            print("Total pipeline images fetched - " + str(len(image_data_list)))
    except:
        raise

    return image_data_list


def query_scanning_v2_pipeline_images(next_cursor):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/scanresults/v2/results' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + \
          '&sortBy=scanDate&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        all_pipeline_images = json.loads(response.text)
        all_images_res = all_pipeline_images["data"]
        next_cursor = all_pipeline_images["page"]["next"]

        for x in all_images_res:
            image_data_dict["imageId"] = x["imageId"]
            image_data_dict["policyStatus"] = x['policyEvaluationsResult'][:4]

            if x["vulnsBySev"] != None:
                image_data_dict["critical"] = x["vulnsBySev"][2]
                image_data_dict["high"] = x["vulnsBySev"][3]
                image_data_dict["medium"] = x["vulnsBySev"][5]
                image_data_dict["low"] = x["vulnsBySev"][6]
                image_data_dict["negligible"] = x["vulnsBySev"][7]
            else:
                image_data_dict["critical"] = 0
                image_data_dict["high"] = 0
                image_data_dict["medium"] = 0
                image_data_dict["low"] = 0
                image_data_dict["negligible"] = 0

            image_data_dict["imagePullString"] = x["imagePullString"]
            imagePull_list = x["imagePullString"].split("/")
            if len(imagePull_list) > 1:
                image_data_dict["repo"] = imagePull_list.pop(0)
                image_data_dict["image_name"] = imagePull_list.pop()
                image_data_dict["reg"] = "/".join(imagePull_list)
            else:
                image_data_dict["repo"] = ""
                image_data_dict["image_name"] = x["imagePullString"]
                image_data_dict["reg"] = ""
            image_data_dict["asset_type"] = ""
            image_data_dict["cluster_name"] = ""
            image_data_dict["namespace_name"] = ""
            image_data_dict["container_name"] = ""
            image_data_dict["workload_name"] = ""
            image_data_dict["workload_type"] = ""
            image_data_dict["node_name"] = ""
            image_data_dict["running"] = "no"

            image_data_dict["in_use_critical"] = 0
            image_data_dict["in_use_high"] = 0
            image_data_dict["in_use_medium"] = 0
            image_data_dict["in_use_low"] = 0
            image_data_dict["in_use_negligible"] = 0

            image_data_dict["exploitCount"] = x["exploitCount"]

            image_data_dict["origin"] = "pipeline"
            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list, next_cursor


def query_scanning_v2_runtime_images_batch():
    image_data_list, next_cursor = query_scanning_v2_runtime_images("")
    try:
        while next_cursor is not None:
            image_data_list_temp, next_cursor = query_scanning_v2_runtime_images(next_cursor)
            image_data_list = image_data_list + image_data_list_temp
            print("Total runtime images fetched - " + str(len(image_data_list)))
    except:
        raise

    return image_data_list


def query_scanning_v2_runtime_images(next_cursor):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/runtime/v2/workflows/results' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + \
          '&order=desc&sort=runningVulnsBySev&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        response_text = json.loads(response.text)
        all_images_res = response_text["data"]
        next_cursor = response_text["page"]["next"]

        a = 0
        for x in all_images_res:

            image_data_dict["resultId"] = x["resultId"]
            image_data_dict["imageId"] = ""
            image_data_dict["imagePullString"] = x["recordDetails"]["mainAssetName"]
            image_data_dict["policyStatus"] = x['policyEvaluationsResult'][:4]

            if x["vulnsBySev"] != None:
                image_data_dict["critical"] = x["vulnsBySev"][2]
                image_data_dict["high"] = x["vulnsBySev"][3]
                image_data_dict["medium"] = x["vulnsBySev"][5]
                image_data_dict["low"] = x["vulnsBySev"][6]
                image_data_dict["negligible"] = x["vulnsBySev"][7]
            else:
                image_data_dict["critical"] = 0
                image_data_dict["high"] = 0
                image_data_dict["medium"] = 0
                image_data_dict["low"] = 0
                image_data_dict["negligible"] = 0

            if x["runningVulnsBySev"] != None:
                image_data_dict["in_use_critical"] = x["runningVulnsBySev"][2]
                image_data_dict["in_use_high"] = x["runningVulnsBySev"][3]
                image_data_dict["in_use_medium"] = x["runningVulnsBySev"][5]
                image_data_dict["in_use_low"] = x["runningVulnsBySev"][6]
                image_data_dict["in_use_negligible"] = x["runningVulnsBySev"][7]
            else:
                image_data_dict["in_use_critical"] = 0
                image_data_dict["in_use_high"] = 0
                image_data_dict["in_use_medium"] = 0
                image_data_dict["in_use_low"] = 0
                image_data_dict["in_use_negligible"] = 0

            image_data_dict["asset_name"] = x["recordDetails"]["mainAssetName"]
            imagePull_list = x["recordDetails"]["mainAssetName"].split("/")
            if len(imagePull_list) > 1:
                image_data_dict["repo"] = imagePull_list.pop(0)
                image_data_dict["image_name"] = imagePull_list.pop()
                image_data_dict["reg"] = "/".join(imagePull_list)
            else:
                image_data_dict["repo"] = ""
                image_data_dict["image_name"] = x["recordDetails"]["mainAssetName"]
                image_data_dict["reg"] = ""

            image_data_dict["asset_type"] = x["recordDetails"]["labels"]["asset.type"]
            image_data_dict["cluster_name"] = x["recordDetails"]["labels"]["kubernetes.cluster.name"]

            if image_data_dict["asset_type"] == "workload":
                image_data_dict["namespace_name"] = x["recordDetails"]["labels"]["kubernetes.namespace.name"]
                image_data_dict["container_name"] = x["recordDetails"]["labels"]["kubernetes.pod.container.name"]
                image_data_dict["workload_name"] = x["recordDetails"]["labels"]["kubernetes.workload.name"]
                image_data_dict["workload_type"] = x["recordDetails"]["labels"]["kubernetes.workload.type"]
                image_data_dict["node_name"] = ""
            elif image_data_dict["asset_type"] == "host":
                image_data_dict["node_name"] = x["recordDetails"]["labels"]["kubernetes.node.name"]
                image_data_dict["cluster_name"] = ""
                image_data_dict["namespace_name"] = ""
                image_data_dict["container_name"] = ""
                image_data_dict["workload_name"] = ""
                image_data_dict["workload_type"] = ""

            image_data_dict["running"] = "yes"
            image_data_dict["origin"] = "runtime"
            image_data_dict["exploitCount"] = x["exploitCount"]

            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
            a = a + 1
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list, next_cursor


def query_scanning_v2_image_details(runtime_images):

    auth_string = "Bearer " + secure_api_token
    a = 0
    for image in runtime_images:
        url = secure_url + '/api/scanning/scanresults/v2/results/' + image["resultId"] + \
        "/vulnPkgs?filter=vulnHasFix = true and vulnIsExploitable = true and vulnIsRunning = true"

        print(a)
        a = a + 1
        if a % 20 == 0:
            print("sleeping for 5 seconds...")
            time.sleep(5)
        while True:
            try:
                response = requests.get(url, headers={"Authorization": auth_string})
                print("url - " + url)
            except Exception as ex:
                logging.error("Received an exception while invoking the url: " + url)
                logging.error(ex)

            if response.status_code == 200:
                response_text = json.loads(response.text)
                matched_total = response_text["page"]["matched"]
                image["fix_exploitable_running"] = matched_total
                break
            else:
                logging.error("Received an error trying to get the response from: " + url)
                logging.error("Error message: " + response.text)
                print(response.headers)
                if "Rate limit exceeded" in response.text:
                    print(response.headers)
                    print("Got rate limit exceeded error message. Sleeping for 2 mins and retrying.")
                    time.sleep(120)
                    print("retrying..." + str(a-1))
                    continue
                else:
                    raise

    return runtime_images


def compliance_prom_exporter():
    auth_string = "Bearer " + secure_api_token
    compliance_data_list = []
    compliance_data_dict = {}

    print("in compliance prom exporter")

    global first_time_running
    global compliances
    if first_time_running:
        url = secure_url + "/api/compliance/v2/tasks?light=true"
        try:
            response = requests.get(url, headers={"Authorization": auth_string})
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise
        if response.status_code == 200:
            compliances = json.loads(response.text)
        else:
            logging.error("Received an error trying to get the response from: " + url)
            logging.error("Error message: " + response.text)
            raise

    for compliance in compliances:

        if compliance["state"] == "Complete" and len(compliance["counts"]["controls"]) > 0:

            compliance_data_dict["name"] = compliance["name"]
            compliance_data_dict["type"] = compliance["type"]

            compliance_data_dict["schema"] = compliance["schema"]
            compliance_data_dict["framework"] = compliance["framework"]
            compliance_data_dict["version"] = compliance["version"]
            compliance_data_dict["platform"] = compliance["platform"]
            # compliance_data_dict["control_pass"] = str(compliance["counts"]["controls"]["pass"])
            # compliance_data_dict["control_fail"] = str(compliance["counts"]["controls"]["fail"])
            # compliance_data_dict["control_warn"] = str(compliance["counts"]["controls"]["warn"])
            # compliance_data_dict["control_pass_percent"] = str(compliance["counts"]["controls"]["passPercent"])
            # compliance_data_dict["control_total"] = str(compliance["counts"]["controls"]["pass"] + compliance["counts"]["controls"]["fail"] + compliance["counts"]["controls"]["warn"])

            # compliance_data_list.append(compliance_data_dict.copy())
            # compliance_data_dict.clear()

            url = secure_url + "/api/compliance/v2/tasks/" + str(compliance["id"]) + "/reports/" + compliance[
                "lastRunCompletedId"]
            # url = secure_url + '/api/compliance/v1/report?detail=false&compliance=' + compliance + '&environment=Kubernetes&output=json'
            try:
                response = requests.get(url, headers={"Authorization": auth_string})
            except Exception as ex:
                logging.error("Received an exception while invoking the url: " + url)
                logging.error(ex)
                raise

            if response.status_code == 200:
                compliance_report = json.loads(response.text)
                for family in compliance_report["families"]:
                    compliance_data_dict["family"] = family["name"]
                    # compliance_data_dict["pass"] = family["counts"]["controls"]
                    compliance_data_dict["control_pass"] = str(family["counts"]["controls"]["pass"])
                    compliance_data_dict["control_fail"] = str(family["counts"]["controls"]["fail"])
                    compliance_data_dict["control_warn"] = str(family["counts"]["controls"]["warn"])
                    compliance_data_dict["control_pass_percent"] = str(family["counts"]["controls"]["passPercent"])
                    compliance_data_dict["control_total"] = str(
                        family["counts"]["controls"]["pass"] + family["counts"]["controls"]["fail"] +
                        family["counts"]["controls"]["warn"])
                    compliance_data_list.append(compliance_data_dict.copy())

                # compliance_data_list.append(compliance_data_dict.copy())
                compliance_data_dict.clear()
            elif response.reason == 'No Content':
                compliance_data_dict.clear()
            # for testing purpose, I am ignoring the error and treating as no content
            # else:
            #     logging.error("Received an error trying to get the response from: " + url)
            #     logging.error("Error message: " + response.text)
            #     raise

    return compliance_data_list


def benchmark_prom_exporter():
    authString = "Bearer " + secure_api_token
    benchmark_data_list = []
    benchmark_data_dict = {}

    print("in benchmark prom exporter")

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
                    benchmark_data_dict["resource_pass"] = str(benchmark["counts"]["resources"]["pass"])
                    benchmark_data_dict["resource_fail"] = str(benchmark["counts"]["resources"]["fail"])
                    benchmark_data_dict["resource_warn"] = str(benchmark["counts"]["resources"]["warn"])
                    benchmark_data_dict["control_pass"] = str(benchmark["counts"]["controls"]["pass"])
                    benchmark_data_dict["control_fail"] = str(benchmark["counts"]["controls"]["fail"])
                    benchmark_data_dict["control_warn"] = str(benchmark["counts"]["controls"]["warn"])
                    if "kubernetes.cluster.name" in benchmark["labels"]:
                        benchmark_data_dict["cluster_name"] = str(benchmark["labels"]["kubernetes.cluster.name"])
                    else:
                        benchmark_data_dict["cluster_name"] = ""
                    if "kubernetes.node.name" in benchmark["labels"]:
                        benchmark_data_dict["node_name"] = str(benchmark["labels"]["kubernetes.node.name"])
                    else:
                        benchmark_data_dict["node_name"] = ""

                    benchmark_data_list.append(benchmark_data_dict.copy())
                    benchmark_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        # logging.error("Error message: " + response.text)
        raise

    return benchmark_data_list


def iam_prom_exporter():
    try:
        iam_policies = query_iam_policies_batch()
        iam_users = query_iam_users_roles_batch("user")
        iam_roles = query_iam_users_roles_batch("role")



    except:
        raise

    return iam_policies, iam_users, iam_roles


def query_iam_policies_batch():
    policy_list, next_cursor = query_iam_policies("")
    try:
        while next_cursor != "":
            policy_list_temp, next_cursor = query_iam_policies(next_cursor)
            policy_list = policy_list + policy_list_temp
    except:
        raise

    return policy_list


def query_iam_policies(next_cursor):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/cloud/v2/policies' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + '&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    policy_data_list = []
    policy_data_dict = {}

    if response.status_code == 200:
        all_policies_temp = json.loads(response.text)
        all_policies = all_policies_temp["data"]
        next_cursor = all_policies_temp["options"]["next"]

        for x in all_policies:
            policy_data_dict["policyName"] = x["policyName"]
            policy_data_dict["policyType"] = x["policyType"]
            policy_data_dict["actorsTotal"] = len(x['actors'])
            policy_data_dict["numPermissionsGiven"] = x["numPermissionsGiven"]
            policy_data_dict["numPermissionsUnused"] = x["numPermissionsUnused"]
            policy_data_dict["riskCategory"] = x["riskCategory"]
            policy_data_dict["riskyPermissions"] = x["riskyPermissions"]
            policy_data_dict["riskScore"] = x["riskScore"]
            policy_data_dict["excessiveRiskCategory"] = x["excessiveRiskCategory"]
            policy_data_dict["excessiveRiskyPermissions"] = x["excessiveRiskyPermissions"]
            policy_data_dict["excessiveRiskScore"] = x["excessiveRiskScore"]
            policy_data_dict["customerName"] = customer_name

            policy_data_list.append(policy_data_dict.copy())
            policy_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return policy_data_list, next_cursor


def query_iam_users_roles_batch(kind):
    user_list, next_cursor = query_iam_users_roles("", kind)
    try:
        while next_cursor != "":
            user_list_temp, next_cursor = query_iam_users_roles(next_cursor, kind)
            user_list = user_list + user_list_temp
    except:
        raise

    return user_list


def query_iam_users_roles(next_cursor, kind):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/cloud/v2/users' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + '&kind=' + kind + '&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    user_role_data_list = []
    user_role_data_dict = {}

    if response.status_code == 200:
        all_users_roles_temp = json.loads(response.text)
        all_users_roles = all_users_roles_temp["data"]
        next_cursor = all_users_roles_temp["options"]["next"]


        admin_risk = "Admin"
        inactive_risk = "Inactive"
        no_mfa_risk = "No MFA"
        key_1_not_rotated_risk = "Access Key 1 Not Rotated"
        key_2_not_rotated_risk = "Access Key 2 Not Rotated"
        multiple_keys_risk = "Multiple Access Keys Active"

        a = 0
        for x in all_users_roles:
            user_role_data_dict["actorName"] = x["actorName"]
            user_role_data_dict["policiesTotal"] = len(x['policies'])
            user_role_data_dict["numPermissionsGiven"] = x["numPermissionsGiven"]
            user_role_data_dict["effectivePermissionsCount"] = x["effectivePermissionsCount"]
            user_role_data_dict["numPermissionsUnused"] = x["numPermissionsUnused"]
            user_role_data_dict["numPermissionsUsed"] = x["numPermissionsUsed"]
            user_role_data_dict["riskCategory"] = x["riskCategory"]
            user_role_data_dict["riskyPermissions"] = x["riskyPermissions"]
            user_role_data_dict["riskScore"] = x["riskScore"]
            user_role_data_dict["excessiveRiskCategory"] = x["excessiveRiskCategory"]
            user_role_data_dict["excessiveRiskyPermissions"] = x["excessiveRiskyPermissions"]
            user_role_data_dict["excessiveRiskScore"] = x["excessiveRiskScore"]
            user_role_data_dict["customerName"] = customer_name

            risk_list = x["labels"]["risk"]

            user_role_data_dict["admin"] = "no"
            user_role_data_dict["inactive"] = "no"
            user_role_data_dict["no_mfa"] = "no"
            user_role_data_dict["key1_not_rotated"] = "no"
            user_role_data_dict["key2_not_rotated"] = "no"
            user_role_data_dict["multiple_keys"] = "no"

            if risk_list is not None:
                for risk in risk_list:
                    if risk == admin_risk:
                        user_role_data_dict["admin"] = "yes"
                    elif risk == inactive_risk:
                        user_role_data_dict["inactive"] = "yes"
                    elif risk == no_mfa_risk:
                        user_role_data_dict["no_mfa"] = "yes"
                    elif risk == key_1_not_rotated_risk:
                        user_role_data_dict["key1_not_rotated"] = "yes"
                    elif risk == key_2_not_rotated_risk:
                        user_role_data_dict["key2_not_rotated"] = "yes"
                    elif risk == multiple_keys_risk:
                        user_role_data_dict["multiple_keys"] = "yes"

            user_role_data_list.append(user_role_data_dict.copy())
            user_role_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return user_role_data_list, next_cursor



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


def print_info():
    print("-------------------------------------")
    print("Received request to scrape prometheus metrics from:")
    print("secure_url: " + secure_url)
    print("port: " + str(prom_exp_url_port))
    print("scheduled_run_minutes: " + str(scheduled_run_minutes))
    print("customer_name: " + customer_name)
    print("Querying for: " + str(query_features_list))
    print("-------------------------------------")


if __name__ == '__main__':
    start_http_server(prom_exp_url_port)
    REGISTRY.register(SecureMetricsCollector())
    while True:
        time.sleep(600)