.. _doc_krill_config:
.. highlight:: none

Configuration options
=====================

Introduction
------------

Krill can be tweaked using a lot of options in the config file. The config
file can be found in `/etc/krill.conf`. Default installations of Krill set 
three options: `admin_token`, `storage_uri`, and `log_type`. Changes to the
config file will be applied after Krill is restarted. Most of the time you 
will not need to change any of these configuration variables. The
configuration file format is TOML.

Options
-------


**ip**


**port**


**https_mode**


**unix_socket_enabled**


**unix_socket**


**unix_users**


**storage_uri**


**use_history_cache**


**tls_keys_dir**


**repo_dir**


**ta_support_enabled**


**ta_signer_enabled**


**pid_file**


**service_uri: Option<uri:**


**log_level**


**log_type**


**log_file**


**syslog_facility**


**admin_token**


**auth_type**


**auth_users**


**auth_openidconnect**


**auth_roles**


**default_signer**


**one_off_signer**


**signer_probe_retry_seconds**


**signers**


**ca_refresh_seconds**


**ca_refresh_jitter_seconds**


**ca_refresh_parents_batch_size**


**suspend_child_after_inactive_seconds**


**suspend_child_after_inactive_hours**


**post_limit_api**


**post_limit_rfc8181**


**rfc8181_log_dir**


**post_limit_rfc6492**


**post_protocol_msg_timeout_seconds**


**rfc6492_log_dir**


**bgp_api_enabled**


**bgp_api_uri**


**bgp_api_cache_seconds**


**roa_aggregate_threshold**


**roa_deaggregate_threshold**


.. 
    Start issuance_timing

**timing_publish_next_hours**


**timing_publish_next_jitter_hours**


**timing_publish_hours_before_next**


**timing_child_certificate_valid_weeks**


**timing_child_certificate_reissue_weeks_before**


**timing_roa_valid_weeks**


**timing_roa_reissue_weeks_before**


**timing_aspa_valid_weeks**


**timing_aspa_reissue_weeks_before**


**timing_bgpsec_valid_weeks**


**timing_bgpsec_reissue_weeks_before**


..
    End issuance_timing


..
    Start rrdp_updates_config

**rrdp_delta_files_min_nr**


**rrdp_delta_files_min_seconds**


**rrdp_delta_files_max_nr**


**rrdp_delta_files_max_seconds**


**rrdp_delta_interval_min_seconds**


**rrdp_files_archive**


..
    End rrdp_updates_config


..
    Start metrics

**metrics_hide_ca_details**


**metrics_hide_child_details**


**metrics_hide_publisher_details**


**metrics_hide_roa_details**


..
    End metrics


**testbed**

*ta_aia*


*ta_uri*


*rrdp_base_uri*


*rsync_jail*


**benchmark**

*cas*


*ca_roas*


**ta_timing**

*certificate_validity_years*


*issued_certificate_validity_weeks*


*issued_certificate_reissue_weeks_before*


*mft_next_update_weeks*


*signed_message_validity_days*


