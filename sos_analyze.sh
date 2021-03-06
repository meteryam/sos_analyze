#!/bin/bash

#
# Created ....: 03/04/2019
# Developer ..: Waldirio M Pinheiro <waldirio@gmail.com / waldirio@redhat.com>
# Purpose ....: Analyze sosreport and summarize the information (focus on Satellite info)
#

FOREMAN_REPORT="/tmp/$$.log"



main()
{
  > $FOREMAN_REPORT

  #sos_path=$1
  #base_dir=$sos_path
  #final_name=$(echo $base_dir | sed -e 's#/$##g' | grep -o sos.* | awk -F"/" '{print $NF}')

#  if [ ! -f $base_dir/version.txt ]; then
#    echo "This is not a sosreport dir, please inform the path to the correct one."
#    exit 1
#  fi

  # detect base directory

  base_dir=""
  sos_subdir=`ls -d $1/sosreport-* $1/foreman-debug-* $1/spacewalk-debug 2>/dev/null | grep . | head -1`

  if [ -d conf ] || [ -d sos_commands ] || [ -f version.txt ] || [ -f hammer-ping ]; then

    base_dir=`pwd`

  elif [ -d $1/conf ] || [ -d $1/sos_commands ] || [ -f $1/version.txt ] || [ -f $1/hammer-ping ]; then

    base_dir="$1"

  elif [ -d $sos_subdir/conf ] || [ -d $sos_subdir/sos_commands ] || [ -f $sos_subdir/version.txt ] || [ -f $sos_subdir/hammer-ping ]; then

    base_dir="$sos_subdir"

  else

    echo "This is not a sosreport dir, please inform the path to the correct one."
    exit 1

  fi

  sos_path=$base_dir
  final_name=$(echo $base_dir | sed -e 's#/$##g' | grep -o sos.* | awk -F"/" '{print $NF}')

  # configure the base_foreman variable based on the presence of foreman-debug directory

  if [ -d $base_dir/sos_commands/foreman/foreman-debug ]; then
    base_foreman="/sos_commands/foreman/foreman-debug/"
    #sos_version="old"
  else
    #sos_version="new"
    base_foreman=""
  fi

  echo "The sosreport is: $base_dir"												| tee -a $FOREMAN_REPORT

  consolidate_differences

  #report $base_dir $sub_dir $base_foreman $sos_version
  report $base_dir $base_foreman $sos_version
}

log_tee()
{
  export GREP_COLORS='ms=01;33'
  echo $1 | egrep --color=always "^|\#" | tee -a $FOREMAN_REPORT
  export GREP_COLORS='ms=01;31'
}

log()
{
  echo "$1" >> $FOREMAN_REPORT
}

log_cmd()
{
  echo "$@" | bash &>> $FOREMAN_REPORT
}


# The CSVLINKS variable contains files to which we want to link, along with alternate filenames found in older sosreport versions, foreman-debug files and satellite-debug files.

CSVLINKS="sos_commands/block/blkid_-c_.dev.null,blkid
sos_commands/boot/efibootmgr_-v,efibootmgr
sos_commands/candlepin/du_-sh_.var.lib.candlepin,hornetq_disk_space
sos_commands/cron/root_crontab,crontab_-l
sos_commands/date/date,timestamp
sos_commands/filesys/df_-ali_-x_autofs,df_-ali
sos_commands/filesys/df_-al_-x_autofs,df_-al
sos_commands/foreman/bundle_--local_--gemfile_.usr.share.foreman.Gemfile,bundle_list
sos_commands/foreman/foreman-selinux-relabel_-nv,foreman_filecontexts
sos_commands/foreman/ls_-lanR_.root.ssl-build,katello_ssl_build_dir
sos_commands/foreman/ls_-lanR_.usr.share.foreman.config.hooks,foreman_hooks_list
sos_commands/foreman/passenger-memory-stats,passenger_memory
sos_commands/foreman/passenger-status_--show_backtraces,passenger_status_backtraces
sos_commands/foreman/passenger-status_--show_pool,passenger_status_pool
sos_commands/foreman/passenger-status_--show_requests,passenger_status_requests
sos_commands/foreman/ping_-c1_-W1_localhost,ping_localhost
sos_commands/foreman/scl_enable_tfm_gem_list,gem_list_scl
sos_commands/kernel/modinfo_ALL_MODULES,modinfo_tpm_tpm_tis_libata_efivars_tcp_cubic_kernel_printk_kgdb_spurious_pstore_dynamic_debug_pcie_aspm_pci_hotplug_pciehp_acpiphp_intel_idle_acpi_pci_slot_processor_thermal_acpi_memhotplug_battery_keyboard_vt_8250_kgdboc_kgdbts_scsi_mod_pcmcia_core_pcmci,modinfo_nfsd_exportfs_auth_rpcgss_usb_storage_ipmi_devintf_ipmi_
sos_commands/kernel/uname_-a,uname
sos_commands/libraries/ldconfig_-p_-N_-X,ldconfig_-p
sos_commands/lvm2/lvs_-a_-o_lv_tags_devices_lv_kernel_read_ahead_lv_read_ahead_stripes_stripesize_--config_global_locking_type_0_metadata_read_only_1,lvs_-a_-o_lv_tags_devices_--config_global_locking_type_0
sos_commands/lvm2/pvs_-a_-v_-o_pv_mda_free_pv_mda_size_pv_mda_count_pv_mda_used_count_pe_start_--config_global_locking_type_0_metadata_read_only_1,pvs_-a_-v_-o_pv_mda_free_pv_mda_size_pv_mda_count_pv_mda_used_count_pe_start_--config_global_locking_type_0
sos_commands/lvm2/pvscan_-v_--config_global_locking_type_0_metadata_read_only_1,pvscan_-v_--config_global_locking_type_0
sos_commands/lvm2/vgdisplay_-vv_--config_global_locking_type_0_metadata_read_only_1,vgdisplay_-vv_--config_global_locking_type_0
sos_commands/lvm2/vgscan_-vvv_--config_global_locking_type_0_metadata_read_only_1,vgscan_-vvv_--config_global_locking_type_0
sos_commands/lvm2/vgs_-v_-o_vg_mda_count_vg_mda_free_vg_mda_size_vg_mda_used_count_vg_tags_--config_global_locking_type_0_metadata_read_only_1,vgs_-v_-o_vg_mda_count_vg_mda_free_vg_mda_size_vg_mda_used_count_vg_tags_--config_global_locking_type_0
sos_commands/networking/ip_-d_address,ip_address,ip_a
sos_commands/networking/ip_neigh_show_nud_noarp,ip_neigh_show
sos_commands/networking/ip_route_show_table_all,ip_r
sos_commands/networking/ip_-s_-d_link,ip_-s_link
sos_commands/networking/iptables_-t_filter_-nvL,iptables_-t_mangle_-nvL
sos_commands/networking/iptables_-vnxL,iptables_-t_nat_-nvL,iptables
sos_commands/networking/netstat_-W_-agn,netstat_-agn
sos_commands/networking/netstat_-W_-neopa,netstat_-neopa,netstat
sos_commands/networking/route_-n,route
sos_commands/pam/ls_-lanF_.lib_.security,ls_-laF_.lib.security.pam__so
sos_commands/pci/lspci_-nnvv,lspci_-nvv
sos_commands/postgresql/du_-sh_.var.lib.pgsql,postgres_disk_space
sos_commands/process/lsof_-b_M_-n_-l_-c,lsof_-b_M_-n_-l
sos_commands/process/ps_auxwww,process_list
sos_commands/process/ps_-elfL,ps-elfm
sos_commands/puppet/facter,facts
sos_commands/puppet/ls_-lanR_.etc.puppetlabs.code.modules,puppet_manifests_tree
sos_commands/puppet/ls_-lanR_.etc.puppet.modules,puppet_manifests_tree
sos_commands/puppet/puppet_--version,version_puppet
sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V,sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-f,rpm_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_.b,installed_packages,rpm-manifest
sos_commands/satellite/rhn-charsets,database-character-sets
sos_commands/satellite/rhn-schema-version,database-schema-version
sos_commands/selinux/semanage_fcontext_-l,selinux_fcontext
sos_commands/tftpserver/ls_-lanR_.tftpboot,tftpboot_tree
sos_commands/selinux/semodule_-l,selinux_modules
sos_commands/hardware/dmesg_.bin.grep_-e_e820._-e_agp,dmesg_grep_-e_e820._-e_aperature
sos_commands/networking/ifconfig_-a,ifconfig
var/log/audit/audit.log,selinux_denials.log
sos_commands/alternatives/alternatives_--display_elspec
sos_commands/alternatives/alternatives_--display_emacs.etags
sos_commands/alternatives/alternatives_--display_java
sos_commands/alternatives/alternatives_--display_jaxp_parser_impl
sos_commands/alternatives/alternatives_--display_jaxp_transform_impl
sos_commands/alternatives/alternatives_--display_jre_1.8.0
sos_commands/alternatives/alternatives_--display_jre_1.8.0_openjdk
sos_commands/alternatives/alternatives_--display_jre_openjdk
sos_commands/alternatives/alternatives_--display_jsp
sos_commands/alternatives/alternatives_--display_libnssckbi.so.x86_64
sos_commands/alternatives/alternatives_--display_mta
sos_commands/alternatives/alternatives_--display_nmap
sos_commands/alternatives/alternatives_--display_servlet
sos_commands/alternatives/alternatives_--list
sos_commands/alternatives/alternatives_--version
sos_commands/alternatives/rpm_-V_chkconfig
sos_commands/ansible/ansible_all_-m_ping_-vvvv
sos_commands/ansible/ansible_--version
sos_commands/ansible/rpm_-V_ansible
sos_commands/apache/apachectl_-M
sos_commands/apache/apachectl_-S
sos_commands/apache/rpm_-V_httpd
sos_commands/auditd/auditctl_-l
sos_commands/auditd/auditctl_-s
sos_commands/auditd/ausearch_--input-logs_-m_avc_user_avc_-ts_today
sos_commands/auditd/rpm_-V_audit
sos_commands/block/blockdev_--report
sos_commands/block/lsblk
sos_commands/block/lsblk_-D
sos_commands/block/lsblk_-f_-a_-l
sos_commands/block/lsblk_-t
sos_commands/block/ls_-lanR_.dev
sos_commands/block/ls_-lanR_.sys.block
sos_commands/block/rpm_-V_util-linux
sos_commands/boot/lsinitrd
sos_commands/boot/ls_-lanR_.boot
sos_commands/boot/mokutil_--sb-state
sos_commands/boot/rpm_-V_grub2_grub2-common
sos_commands/btrfs/btrfs_filesystem_show
sos_commands/btrfs/btrfs_version
sos_commands/btrfs/rpm_-V_btrfs-progs
sos_commands/candlepin/candlepin_db_tables_sizes
sos_commands/candlepin/rpm_-V_candlepin
sos_commands/ceph/ceph_df
sos_commands/ceph/ceph-disk_list
sos_commands/ceph/ceph_fs_dump_--format_json-pretty
sos_commands/ceph/ceph_fs_ls
sos_commands/ceph/ceph_health_detail
sos_commands/ceph/ceph_health_detail_--format_json-pretty
sos_commands/ceph/ceph_mon_dump
sos_commands/ceph/ceph_mon_stat
sos_commands/ceph/ceph_mon_status
sos_commands/ceph/ceph_osd_crush_dump
sos_commands/ceph/ceph_osd_crush_show-tunables
sos_commands/ceph/ceph_osd_df_tree
sos_commands/ceph/ceph_osd_dump
sos_commands/ceph/ceph_osd_stat
sos_commands/ceph/ceph_osd_tree
sos_commands/ceph/ceph_pg_dump
sos_commands/ceph/ceph_quorum_status
sos_commands/ceph/ceph_report
sos_commands/ceph/ceph_status
sos_commands/ceph/ceph_versions
sos_commands/ceph/rpm_-V_librados2
sos_commands/cgroups/systemd-cgls
sos_commands/chrony/chronyc_activity
sos_commands/chrony/chronyc_-n_clients
sos_commands/chrony/chronyc_-n_sources
sos_commands/chrony/chronyc_ntpdata
sos_commands/chrony/chronyc_serverstats
sos_commands/chrony/chronyc_sourcestats
sos_commands/chrony/chronyc_tracking
sos_commands/chrony/journalctl_--no-pager_--unit_chronyd
sos_commands/chrony/rpm_-V_chrony
sos_commands/crypto/fips-mode-setup_--check
sos_commands/crypto/update-crypto-policies_--is-applied
sos_commands/crypto/update-crypto-policies_--show
sos_commands/date/date_--utc
sos_commands/date/hwclock
sos_commands/dbus/busctl_list_--no-pager
sos_commands/dbus/busctl_status
sos_commands/dbus/rpm_-V_dbus
sos_commands/devicemapper/dmsetup_info_-c
sos_commands/devicemapper/dmsetup_ls_--tree
sos_commands/devicemapper/dmsetup_status
sos_commands/devicemapper/dmsetup_table
sos_commands/devicemapper/dmstats_list
sos_commands/devicemapper/dmstats_print_--allregions
sos_commands/devicemapper/rpm_-V_device-mapper
sos_commands/devices/udevadm_info_--export-db
sos_commands/docker/journalctl_--no-pager_--unit_docker
sos_commands/docker/ls_-alhR_.etc.docker
sos_commands/dracut/dracut_--list-modules
sos_commands/dracut/dracut_--print-cmdline
sos_commands/dracut/rpm_-V_dracut
sos_commands/filesys/findmnt
sos_commands/filesys/lslocks
sos_commands/filesys/ls_-ltradZ_.tmp
sos_commands/filesys/mount_-l
sos_commands/firewalld/firewall-cmd_--direct_--get-all-chains
sos_commands/firewalld/firewall-cmd_--direct_--get-all-passthroughs
sos_commands/firewalld/firewall-cmd_--direct_--get-all-rules
sos_commands/firewalld/firewall-cmd_--get-log-denied
sos_commands/firewalld/firewall-cmd_--list-all-zones
sos_commands/firewalld/firewall-cmd_--permanent_--direct_--get-all-chains
sos_commands/firewalld/firewall-cmd_--permanent_--direct_--get-all-passthroughs
sos_commands/firewalld/firewall-cmd_--permanent_--direct_--get-all-rules
sos_commands/firewalld/firewall-cmd_--permanent_--list-all-zones
sos_commands/firewalld/firewall-cmd_--state
sos_commands/firewalld/nft_list_ruleset
sos_commands/firewalld/rpm_-V_firewalld
sos_commands/foreman/dynflow_actions
sos_commands/foreman/dynflow_execution_plans
sos_commands/foreman/dynflow_schema_info
sos_commands/foreman/dynflow_steps
sos_commands/foreman/foreman_auth_table
sos_commands/foreman/foreman_db_tables_sizes
sos_commands/foreman/foreman-maintain_service_status,katello_service_status
sos_commands/foreman/foreman_settings_table
sos_commands/foreman/foreman_tasks_tasks,foreman_tasks_tasks.csv
sos_commands/foreman/hammer_ping
sos_commands/foreman/rpm_-V_foreman_foreman-proxy
sos_commands/foreman/foreman-debug/mongodb_disk_space
sos_commands/grub2/grub2-mkconfig
sos_commands/grub2/ls_-lanR_.boot
sos_commands/grub2/rpm_-V_grub2_grub2-common
sos_commands/hardware/dmidecode
sos_commands/host/hostid
sos_commands/host/hostname
sos_commands/host/hostnamectl_status
sos_commands/host/hostname_-f
sos_commands/host/uptime
sos_commands/i18n/locale
sos_commands/insights/rpm_-V_insights-client
sos_commands/ipmitool/ipmitool_chassis_status
sos_commands/ipmitool/ipmitool_fru_print
sos_commands/ipmitool/ipmitool_mc_info
sos_commands/ipmitool/ipmitool_sdr_info
sos_commands/ipmitool/ipmitool_sel_info
sos_commands/ipmitool/ipmitool_sel_list
sos_commands/ipmitool/ipmitool_sensor_list
sos_commands/ipmitool/rpm_-V_ipmitool
sos_commands/java/alternatives_--display_java
sos_commands/java/readlink_-f_.usr.bin.java
sos_commands/katello/db_table_size
sos_commands/katello/katello_repositories
sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671,qpid-stat_-q_--ssl-certificate_.etc.pki.pulp.qpid.client.crt_-b_amqps_..localhost_5671,qpid-stat-q
sos_commands/katello/rpm_-V_katello
sos_commands/kdump/rpm_-V_kexec-tools
sos_commands/kernel/bpftool_-j_map_list
sos_commands/kernel/bpftool_-j_prog_list
sos_commands/kernel/dkms_status
sos_commands/kernel/dmesg
sos_commands/kernel/ls_-lt_.sys.kernel.slab
sos_commands/kernel/lsmod
sos_commands/kernel/rpm_-V_kernel
sos_commands/kernel/sysctl_-a
sos_commands/krb5/klist_-ket_.etc.krb5.keytab
sos_commands/krb5/klist_-ket_.var.kerberos.krb5kdc..k5
sos_commands/krb5/rpm_-V_krb5-libs
sos_commands/last/last
sos_commands/last/lastlog
sos_commands/last/last_reboot
sos_commands/last/last_shutdown
sos_commands/ldap/certutil_-L_-d_.etc.openldap
sos_commands/ldap/rpm_-V_openldap
sos_commands/libraries/ld_so_cache
sos_commands/libvirt/ls_-lR_.var.lib.libvirt.qemu
sos_commands/logrotate/logrotate_debug
sos_commands/md/mdadm_-D_.dev.md
sos_commands/memory/free
sos_commands/memory/free_-m
sos_commands/memory/lsmem_-a_-o_RANGE_SIZE_STATE_REMOVABLE_ZONES_NODE_BLOCK
sos_commands/memory/swapon_--bytes_--show
sos_commands/memory/swapon_--summary_--verbose
sos_commands/multipath/multipathd_show_config
sos_commands/multipath/multipath_-ll
sos_commands/multipath/multipath_-t
sos_commands/multipath/multipath_-v4_-ll
sos_commands/networking/biosdevname_-d
sos_commands/networking/bridge_-d_vlan_show
sos_commands/networking/bridge_-s_-s_-d_link_show
sos_commands/networking/bridge_-s_-s_-d_-t_fdb_show
sos_commands/networking/bridge_-s_-s_-d_-t_mdb_show
sos_commands/networking/ifenslave_-a
sos_commands/networking/ip_-4_rule
sos_commands/networking/ip_-6_route_show_table_all
sos_commands/networking/ip_-6_rule
sos_commands/networking/ip_maddr_show
sos_commands/networking/ip_mroute_show
sos_commands/networking/ip_netns
sos_commands/networking/ip_-o_addr
sos_commands/networking/ip_-s_-s_neigh_show
sos_commands/networking/netstat_-s
sos_commands/networking/plotnetcfg
sos_commands/networking/tc_-s_qdisc_show
sos_commands/networkmanager/nmcli_con
sos_commands/networkmanager/nmcli_con_show_--active
sos_commands/networkmanager/nmcli_dev
sos_commands/networkmanager/nmcli_general_status
sos_commands/networkmanager/rpm_-V_NetworkManager
sos_commands/nis/domainname
sos_commands/nss/rpm_-V_nss-tools_nss-sysinit_nss-util_nss-softokn_nss_nss-pem_nss-softokn-freebl
sos_commands/openshift/oo-diagnostics_-v
sos_commands/openssl/rpm_-V_openssl_openssl-libs
sos_commands/pam/faillock
sos_commands/pam/pam_tally2
sos_commands/pci/lspci_-tv
sos_commands/perl/perl_-V
sos_commands/perl/rpm_-V_perl-parent_perl-File-Temp_perl-Text-ParseWords_perl-Scalar-List-Utils_perl-Encode_perl-Data-Dumper_perl-libs_perl_perl-Compress-Raw-Zlib_perl-Digest_perl-constant_perl-Git_perl-Time-HiRes_perl-threads_perl-Time-Local_perl-Pod-Usage_perl-Getopt-Lon
sos_commands/podman/ls_-alhR_.etc.cni
sos_commands/podman/podman_images
sos_commands/podman/podman_info
sos_commands/podman/podman_pod_ps
sos_commands/podman/podman_pod_ps_-a
sos_commands/podman/podman_port_--all
sos_commands/podman/podman_ps
sos_commands/podman/podman_ps_-a
sos_commands/podman/podman_stats_--no-stream_--all
sos_commands/podman/podman_version
sos_commands/podman/podman_volume_ls
sos_commands/postfix/mailq
sos_commands/postfix/postconf
sos_commands/postfix/rpm_-V_postfix
sos_commands/postgresql/rpm_-V_postgresql
sos_commands/processor/cpufreq-info
sos_commands/processor/cpuid
sos_commands/processor/cpuid_-r
sos_commands/processor/cpupower_frequency-info
sos_commands/processor/cpupower_idle-info
sos_commands/processor/cpupower_info
sos_commands/processor/lscpu
sos_commands/processor/turbostat_--debug_sleep_10
sos_commands/processor/x86info_-a
sos_commands/process/ps_alxwww
sos_commands/process/ps_auxwwwm
sos_commands/process/ps_axo_flags_state_uid_pid_ppid_pgid_sid_cls_pri_addr_sz_wchan_lstart_tty_time_cmd
sos_commands/process/ps_axo_pid_ppid_user_group_lwp_nlwp_start_time_comm_cgroup
sos_commands/process/pstree
sos_commands/pulp/mongo-collection_sizes
sos_commands/pulp/mongo-db_stats
sos_commands/pulp/mongo-reserved_resources
sos_commands/pulp/mongo-task_status
sos_commands/pulp/pulp-running_tasks
sos_commands/pulp/rpm_-V_pulp-server_pulp-katello
sos_commands/puppet/rpm_-V_puppetserver
sos_commands/python/python2_-V
sos_commands/python/python3_-V
sos_commands/python/python-version
sos_commands/python/rpm_-V_python
sos_commands/qpid_dispatch/qdstat_-a
sos_commands/qpid_dispatch/qdstat_-c
sos_commands/qpid_dispatch/qdstat_-m
sos_commands/qpid_dispatch/qdstat_-n
sos_commands/qpid_dispatch/rpm_-V_qpid-dispatch-router
sos_commands/qpid/ls_-lanR_.var.lib.qpidd
sos_commands/qpid/qpid-cluster
sos_commands/qpid/qpid-config_exchanges
sos_commands/qpid/qpid-config_exchanges_-b
sos_commands/qpid/qpid-config_exchanges_-r
sos_commands/qpid/qpid-config_queues
sos_commands/qpid/qpid-config_queues_-b
sos_commands/qpid/qpid-config_queues_-r
sos_commands/qpid/qpid-ha_query
sos_commands/qpid/qpid-route_link_list
sos_commands/qpid/qpid-route_route_list
sos_commands/qpid/qpid-stat_-b
sos_commands/qpid/qpid-stat_-c
sos_commands/qpid/qpid-stat_-e
sos_commands/qpid/qpid-stat_-g
sos_commands/qpid/qpid-stat_-m
sos_commands/qpid/qpid-stat_-q
sos_commands/qpid/qpid-stat_-u
sos_commands/qpid/rpm_-V_qpid-cpp-server_qpid-tools
sos_commands/release/lsb_release
sos_commands/release/lsb_release_-a
sos_commands/rpm/lsof_D_var_lib_rpm
sos_commands/rpm/package-data
sos_commands/rpm/rpm_-V_rpm-build_rpm-python_rpm-libs_rpm_rpm-build-libs
sos_commands/ruby/gem_list
sos_commands/ruby/gem_--version
sos_commands/ruby/irb_--version
sos_commands/ruby/rpm_-V_ruby_ruby-irb
sos_commands/ruby/ruby_--version
sos_commands/satellite/ls_-lanR_.root.ssl-build
sos_commands/scsi/lsscsi
sos_commands/scsi/sg_map_-x
sos_commands/selinux/ps_auxZww
sos_commands/selinux/selinuxconlist_root
sos_commands/selinux/selinuxdefcon_root
sos_commands/selinux/selinuxexeccon_.bin.passwd
sos_commands/selinux/semanage_interface_-l
sos_commands/selinux/semanage_login_-l
sos_commands/selinux/semanage_module_-l
sos_commands/selinux/semanage_node_-l
sos_commands/selinux/semanage_-o
sos_commands/selinux/semanage_port_-l
sos_commands/selinux/semanage_user_-l
sos_commands/selinux/sestatus
sos_commands/selinux/sestatus_-b
sos_commands/selinux/sestatus_-v
sos_commands/services/chkconfig_--list
sos_commands/services/ls_.var.lock.subsys
sos_commands/services/runlevel
sos_commands/soundcard/amixer
sos_commands/soundcard/aplay_-l
sos_commands/soundcard/aplay_-L
sos_commands/squid/rpm_-V_squid
sos_commands/subscription_manager/rct_cat-cert_.etc.pki.product-default.69.pem
sos_commands/subscription_manager/rpm_-V_subscription-manager
sos_commands/subscription_manager/subscription-manager_identity
sos_commands/subscription_manager/subscription-manager_list_--consumed
sos_commands/subscription_manager/subscription-manager_list_--installed
sos_commands/subscription_manager/syspurpose_show
sos_commands/systemd/journalctl_--list-boots
sos_commands/systemd/journalctl_--verify
sos_commands/systemd/ls_-lR_.lib.systemd
sos_commands/systemd/rpm_-V_systemd
sos_commands/systemd/systemctl_list-dependencies
sos_commands/systemd/systemctl_list-jobs
sos_commands/systemd/systemctl_list-machines
sos_commands/systemd/systemctl_list-timers_--all
sos_commands/systemd/systemctl_list-unit-files
sos_commands/systemd/systemctl_list-units
sos_commands/systemd/systemctl_list-units_--failed
sos_commands/systemd/systemctl_show_--all
sos_commands/systemd/systemctl_show-environment
sos_commands/systemd/systemctl_show_service_--all
sos_commands/systemd/systemctl_status_--all
sos_commands/systemd/systemd-analyze
sos_commands/systemd/systemd-analyze_blame
sos_commands/systemd/systemd-analyze_dump
sos_commands/systemd/systemd-analyze_plot.svg
sos_commands/systemd/systemd-delta
sos_commands/systemd/systemd-resolve_--statistics
sos_commands/systemd/systemd-resolve_--status
sos_commands/systemd/timedatectl
sos_commands/system/rpm_-V_glibc-common_glibc_initscripts_zlib
sos_commands/sysvipc/ipcs
sos_commands/sysvipc/ipcs_-u
sos_commands/teamd/rpm_-V_teamd
sos_commands/tftpserver/ls_-lanR_.srv.tftp
sos_commands/tftpserver/rpm_-V_tftp-server
sos_commands/tomcat/rpm_-V_tomcat
sos_commands/tuned/rpm_-V_tuned
sos_commands/tuned/tuned-adm_active
sos_commands/tuned/tuned-adm_list
sos_commands/tuned/tuned-adm_recommend
sos_commands/tuned/tuned-adm_verify
sos_commands/usb/lsusb
sos_commands/usb/lsusb_-t
sos_commands/usb/lsusb_-v
sos_commands/vhostmd/rpm_-V_virt-what
sos_commands/x11/xrandr_--verbose
sos_commands/xfs/xfs_admin_-l_-u_.dev.mapper.rhel_denjht1-root
sos_commands/xfs/xfs_info
sos_commands/xfs/xfs_info_.boot
sos_commands/xinetd/rpm_-V_xinetd
sos_commands/yum/package-cleanup_--dupes
sos_commands/yum/package-cleanup_--problems
sos_commands/yum/plugin-packages
sos_commands/yum/rpm_-V_yum-rhn-plugin_yum-utils_yum-metadata-parser_yum
sos_commands/yum/yum_-C_repolist
sos_commands/yum/yum_history
sos_commands/yum/yum_list_installed
sos_commands/zfs/zfs_get_all
sos_commands/zfs/zfs_list_-t_all_-o_space
sos_commands/zfs/zpool_list
sos_commands/zfs/zpool_status_-vx
sos_commands/abrt/abrt-log
sos_commands/autofs/etc.init.d.autofs_status
sos_commands/cups/lpstat_-d
sos_commands/cups/lpstat_-s
sos_commands/cups/lpstat_-t
sos_commands/dmraid/dmraid_-b
sos_commands/dmraid/dmraid_-r
sos_commands/dmraid/dmraid_-s
sos_commands/dmraid/dmraid_-tay
sos_commands/dmraid/dmraid_-V
sos_commands/ipa/certutil_-L_-d_.etc.httpd.alias
sos_commands/ipa/certutil_-L_-d_.var.lib.pki-ca.alias
sos_commands/ipa/getcert_list
sos_commands/ipa/klist_-ket_.etc.dirsrv.ds.keytab
sos_commands/ipa/klist_-ket_.etc.httpd.conf.ipa.keytab
sos_commands/ipa/ls_-la_.etc.dirsrv.slapd-_.schema
sos_commands/keyutils/keyctl_show
sos_commands/networking/ip6tables_-t_filter_-nvL
sos_commands/networking/ip6tables_-vnxL
sos_commands/ntp/ntpstat
sos_commands/ntp/ntptime
sos_commands/numa/numactl_--hardware
sos_commands/numa/numactl_--show
sos_commands/numa/numastat
sos_commands/numa/numastat_-m
sos_commands/numa/numastat_-n
sos_commands/pci/lspci
sos_commands/samba/testparm_-s_-v
sos_commands/samba/wbinfo_--domain_._-g
sos_commands/samba/wbinfo_--domain_._-u
sos_commands/sunrpc/rpcinfo_-p_localhost
sos_commands/systemtap/stap-report
sos_commands/systemtap/uname_-r
sos_commands/upstart/initctl_--system_list
sos_commands/upstart/initctl_--system_version
sos_commands/upstart/init_--version
sos_commands/upstart/ls_-l_.etc.init
sos_commands/autofs/chkconfig_--list_autofs
sos_commands/autofs/egrep_-e_automount_pid._nfs_.proc.mounts
sos_commands/autofs/mount_egrep_-e_automount_pid._nfs
sos_commands/autofs/ps_auxwww_grep_automount
sos_commands/autofs/rpm_-qV_autofs
sos_commands/bootloader/ls_-laR_.boot
sos_commands/crontab/users_crontabs
sos_commands/dmraid/dmraid_-rD
sos_commands/dmraid/ls_-laR_.dev
sos_commands/dmraid/ls_-laR_.sys.block
sos_commands/dmraid/lvs_-a_-o_devices_--config_global_locking_type_0
sos_commands/dmraid/mdadm_-D_.dev.md
sos_commands/dmraid/multipath_-v4_-ll
sos_commands/dmraid/pvs_-a_-v_--config_global_locking_type_0
sos_commands/dmraid/pvscan_-v_--config_global_locking_type_0
sos_commands/dmraid/systool_-v_-c_-b_scsi
sos_commands/dmraid/udevinfo_-ap_.sys.block.md0
sos_commands/dmraid/udevinfo_-ap_.sys.block.sr0
sos_commands/dmraid/vgdisplay_-vv_--config_global_locking_type_0
sos_commands/dmraid/vgscan_-vvv_--config_global_locking_type_0
sos_commands/dmraid/vgs_-v_--config_global_locking_type_0
sos_commands/emc/powermt_version
sos_commands/emc/usr.symcli.bin.stordaemon_list
sos_commands/emc/usr.symcli.bin.stordaemon_-v_list
sos_commands/emc/usr.symcli.bin.symbcv_list
sos_commands/emc/usr.symcli.bin.symbcv_-v_list
sos_commands/emc/usr.symcli.bin.symcfg_-app_-v_list
sos_commands/emc/usr.symcli.bin.symcfg_-connections_list
sos_commands/emc/usr.symcli.bin.symcfg_-db
sos_commands/emc/usr.symcli.bin.symcfg_-dir_all_-v_list
sos_commands/emc/usr.symcli.bin.symcfg_-fa_all_-port_list
sos_commands/emc/usr.symcli.bin.symcfg_list
sos_commands/emc/usr.symcli.bin.symcfg_list_-lock
sos_commands/emc/usr.symcli.bin.symcfg_list_-lockn_all
sos_commands/emc/usr.symcli.bin.symcfg_-ra_all_-port_list
sos_commands/emc/usr.symcli.bin.symcfg_-sa_all_-port_list
sos_commands/emc/usr.symcli.bin.symcfg_-semaphores_list
sos_commands/emc/usr.symcli.bin.symcfg_-v_list
sos_commands/emc/usr.symcli.bin.symcg_list
sos_commands/emc/usr.symcli.bin.symcg_-v_list
sos_commands/emc/usr.symcli.bin.symcli_-def
sos_commands/emc/usr.symcli.bin.symclone_list
sos_commands/emc/usr.symcli.bin.symdev_list
sos_commands/emc/usr.symcli.bin.symdev_-rdfa_list
sos_commands/emc/usr.symcli.bin.symdev_-rdfa_-v_list
sos_commands/emc/usr.symcli.bin.symdev_-v_list
sos_commands/emc/usr.symcli.bin.symdg_list
sos_commands/emc/usr.symcli.bin.symdg_-v_list
sos_commands/emc/usr.symcli.bin.symevent_list
sos_commands/emc/usr.symcli.bin.symhost_show_-config
sos_commands/emc/usr.symcli.bin.syminq
sos_commands/emc/usr.symcli.bin.syminq_hba_-fibre
sos_commands/emc/usr.symcli.bin.syminq_hba_-scsi
sos_commands/emc/usr.symcli.bin.syminq_-symmids
sos_commands/emc/usr.symcli.bin.syminq_-v
sos_commands/emc/usr.symcli.bin.symmaskdb_list_database
sos_commands/emc/usr.symcli.bin.symmaskdb_-v_list_database
sos_commands/emc/usr.symcli.bin.symmask_list_hba
sos_commands/emc/usr.symcli.bin.symmask_list_logins
sos_commands/emc/usr.symcli.bin.sympd_list
sos_commands/emc/usr.symcli.bin.sympd_list_-vcm
sos_commands/emc/usr.symcli.bin.symrdf_list
sos_commands/emc/usr.symcli.bin.symrdf_-rdfa_list
sos_commands/emc/usr.symcli.bin.symrdf_-rdfa_-v_list
sos_commands/emc/usr.symcli.bin.symrdf_-v_list
sos_commands/emc/usr.symcli.bin.symsnap_list
sos_commands/emc/usr.symcli.bin.symsnap_list_-savedevs
sos_commands/general/dmesg_now
sos_commands/general/tail_sa01
sos_commands/hardware/dmesg_.bin.egrep_3c359_3c59x_3w-9xxx_3w-sas_3w-xxxx_8139cp_8139t
sos_commands/hardware/lshal
sos_commands/libraries/ldconfig_-v
sos_commands/logrotate/logrotate_status
sos_commands/networking/ip_link
sos_commands/nfsserver/nfsstat
sos_commands/nfsserver/rpcinfo_-p_localhost
sos_commands/ntp/ntptrace
sos_commands/rpm/rpm_-Va
sos_commands/selinux/rpm_-q_-V_selinux-policy-strict
sos_commands/selinux/rpm_-q_-V_selinux-policy-targeted
sos_commands/selinux/sestatus_-vb
sos_commands/smartcard/ls_-l_.usr.lib.pam_pkcs11
sos_commands/smartcard/pkcs11_inspect_debug
sos_commands/smartcard/pklogin_finder_debug
sos_commands/soundcard/lspci_grep_-i_audio
sos_commands/soundcard/sndmodules_loaded
sos_commands/startup/service_--status-all
sos_commands/systemtap/rpm_-qa_.bin.egrep_-e_kernel._uname_-r_-e_systemtap_-e_elfutils_
sos_commands/x11/dmesg_grep_-e_agpgart
etc/hosts
etc/selinux/config,selinux_state
ifconfig,ifconfig_-a
chkconfig,chkconfig_--list
proc/cpuinfo
date,date_--utc
df,df_-al,df_-ali,df_-al_-x_autofs,df_-ali_-x_autofs,diskinfo
dmidecode
hostname,hostname_-f
installed-rpms,rpm-manifest
ip_addr,ip_address,ip_a
last
lsb-release,lsb_release
lsmod
lsof,lsof_-b_M_-n_-l,lsof_-b_M_-n_-l_-c
lspci,lspci_-nvv,lspci_-nnvv
mount,mount_-l
netstat,netstat_-W_-neopa,netstat_-neopa
ps,ps_auxwww,ps_auxwwwm,ps_auxww,ps_auxww,ps_-elfL,ps_-elf,ps_axo_flags_state_uid_pid_ppid_pgid_sid_cls_pri_addr_sz_wchan_lstart_tty_time_cmd,ps_axo_pid_ppid_user_group_lwp_nlwp_start_time_comm_cgroup,ps-awfux
pstree
route,route_-n
uname,uname_-a
uptime
vgdisplay,vgdisplay_-vv_--config_global_locking_type_0
database-character-sets,rhn-charsets
database-schema-version,rhn-schema-version"


# The consolidate_differences function looks for files that are expected by our tools if they don't appear in the expected locations.  This can increase the utility of old sosreports and related files.

consolidate_differences()
{
  echo "creating soft links for compatibility..."
  echo

  # create a few basic links

  touch $base_dir/version.txt

  if [ -d $base_dir/usr/lib ] && [ ! -f $base_dir/lib ]; then ln -s usr/lib $base_dir/lib 2>/dev/null; fi

  #mkdir -p $base_dir/sos_commands/foreman/foreman-debug 2>/dev/null


  # this section handles spacewalk-debug files

  if [ -d $base_dir/conf ]; then

        mkdir -p $base_dir/var/log
        ln -s conf $base_dir/etc 2>/dev/null

        if [ -d $base_dir/conf/tomcat/tomcat6 ]; then ln -s tomcat/tomcat6 $base_dir/conf/tomcat6 2>/dev/null; fi

        if [ -d $base_dir/httpd-logs/httpd ]; then ln -s ../../httpd-logs/httpd $base_dir/var/log/httpd 2>/dev/null; fi
        if [ -d $base_dir/tomcat-logs/tomcat6 ]; then ln -s ../../tomcat-logs/tomcat6 $base_dir/var/log/tomcat6 2>/dev/null; fi
        if [ -d $base_dir/rhn-logs/rhn ]; then ln -s ../../rhn-logs/rhn $base_dir/var/log/rhn 2>/dev/null; fi
        if [ -d $base_dir/cobbler-logs ]; then ln -s ../../cobbler-logs $base_dir/var/log/cobbler 2>/dev/null; fi
        if [ -d $base_dir/audit-log ]; then ln -s ../../audit-log i$base_dir/var/log/audit 2>/dev/null; fi
        if [ -d $base_dir/schema-upgrade-logs ]; then ln -s ../../../schema-upgrade-logs $base_dir/var/log/spacewalk/schema-upgrade 2>/dev/null; fi

        #mkdir -p $base_dir/sos_commands/foreman/foreman-debug

    	if [ -d $base_dir/containers ]; then
    		mkdir -p $base_dir/sos_commands/podman
    		if [ -f $base_dir/containers/ps ]; then ln -s ../../containers/ps $base_dir/sos_commands/podman/podman_ps 2>/dev/null; fi
    	fi

  fi


  # this section links directories together to ensure that scripts can find their content

  #if [ -d $base_dir/etc ]; then ln -s ../../../etc $base_dir/sos_commands/foreman/foreman-debug/etc 2>/dev/null; fi
  #if [ -d $base_dir/usr ]; then ln -s ../../../usr $base_dir/sos_commands/foreman/foreman-debug/usr 2>/dev/null; fi
  #if [ -d $base_dir/var ]; then ln -s ../../../var $base_dir/sos_commands/foreman/foreman-debug/var 2>/dev/null; fi

  if [ -d $base_dir/sos_commands/dmraid ] && [ ! -d $base_dir/sos_commands/devicemapper ]; then ln -s dmraid $base_dir/sos_commands/devicemapper 2>/dev/null; fi
  if [ -d $base_dir/sos_commands/lsbrelease ]; then ln -s lsbrelease $base_dir/sos_commands/release 2>/dev/null; fi
  if [ -d $base_dir/sos_commands/printing ]; then ln -s printing $base_dir/sos_commands/cups 2>/dev/null; fi


  # this section populates the sos_commands directory and various links in the root directory of the sosreport

	#LIST_OF_FILES=`find $base_dir -type f 2>/dev/null`

   for MYENTRY in `echo -e "$CSVLINKS"`; do

	# we're separating each comma-separated line into separate entries
	# then we'll check the target folder for each entry in order to find
	# the best match.

	MYARRAY=()
	for i in "`echo $MYENTRY | tr ',' '\n'`"; do
		MYARRAY+=($i)
	done

	count=0
	MYDIR=""
	MATCH=""
	FIRSTFILE=`basename "${MYARRAY[0]}"`
	MYDIR=`dirname "${MYARRAY[0]}"`
	for i in "${MYARRAY[@]}"; do
		let count=$count+1

		MYFILE=`basename $i`
		MATCH=`find $base_dir -type f -name $MYFILE 2>/dev/null | egrep -v '\./containers/ps'`	# containers/ps contains podman processes, not normal processes

		#if [ "$count" -eq 1 ]; then
			#MYDIR=`dirname $i`
			#MATCH=`find $base_dir -type f -name $MYFILE 2>/dev/null | egrep -v '\./containers/ps'`	# containers/ps contains podman processes, not normal processes
		#else
			#MATCH=`find $base_dir -type f -name $i 2>/dev/null`
		#fi

		if [ -f "$MATCH" ] && [ ! -L "$MATCH" ]; then
			if [ ! -f "$base_dir/$MYDIR/$FIRSTFILE" ]; then
				mkdir -p "$base_dir/$MYDIR"
				ln -s -r "$MATCH" "$base_dir/$MYDIR/$FIRSTFILE" 2>/dev/null
			fi
			break
		fi

	done
  done

}

# this is a list of red hat packages installed from the satellite repositories.
# we'll use it later to highlight conflicting third-party packages.

SATPACKAGES="dynflow|foreman|gofer|katello|mongo|passenger|pulp|qpid|satellite|^ansible-2|^ansiblerole-insights-client|^ansible-runner|^candlepin-|^candlepin-selinux|^createrepo_c-|^createrepo_c-libs-|^facter-|^hfsplus-tools-|^hiera-|^kobo-|^libmodulemd-|^libsolv-|^libstemmer-|^libwebsockets-|^liquibase-|^mod_xsendfile-|^ostree-|^pcp-mmvstatsd\-|^puppet|^pycairo-|^spacecmd-|^tracer-common-|^v8|^virt-who-|^yaml-cpp|^python2-amqp-|^python2-ansible-runner-|^python2-anyjson-|^python2-beautifulsoup4-|^python2-celery-|^python2-click-|^python2-crane-|^python2-daemon-|^python2-django-|^python2-future-|^python2-gobject-|^python2-gobject-base-|^python2-isodate-|^python2-itsdangerous-|^python2-jinja2-|^python2-jmespath-|^python2-markupsafe-|^python2-nectar-|^python2-okaara-|^python2-pexpect-|^python2-ptyprocess-|^python2-solv-|^python2-tracer-|^python2-twisted-|^python2-vine-|^python2-werkzeug-|^python-amqp-|^python-anyjson-|^python-argcomplete-|^python-billiard-|^python-blinker-|^python-bson-|^python-celery-|^python-crane-|^python-django-|^python-django-bash-completion-|^python-ecdsa-|^python-flask-|^python-fpconst-|^python-gnupg-|^python-httplib2-|^python-isodate-|^python-itsdangerous-|^python-kid-|^python-kombu-|^python-nectar-|^python-oauth2-|^python-okaara-|^python-passlib-|^python-psutil-|^python-requests-toolbelt-|^python-saslwrapper-|^python-semantic_version-|^python-simplejson-|^python-twisted-core-|^python-twisted-web-|^python-werkzeug-|^python-zope-interface-|^redhat-access-insights-puppet-|^repoview-|^rhel8-kickstart-setup-|^ruby-augeas-|^rubygem-ansi-|^rubygem-apipie-bindings-|^rubygem-awesome_print-|^rubygem-bundler_ext-|^rubygem-clamp-|^rubygem-concurrent-ruby-|^rubygem-facter-|^rubygem-faraday-|^rubygem-faraday_middleware-|^rubygem-fast_gettext-|^rubygem-ffi-|^rubygem-gssapi-|^rubygem-hashie-|^rubygem-highline-|^rubygem-infoblox-|^rubygem-journald-logger-|^rubygem-journald-native-|^rubygem-jwt-|^rubygem-kafo-|^rubygem-kafo_parsers-|^rubygem-kafo_wizards-|^rubygem-little-plugger-|^rubygem-logging-|^rubygem-logging-journald-|^rubygem-mime-types-|^rubygem-multi_json-|^rubygem-multipart-post-|^rubygem-netrc-|^rubygem-net-ssh-|^rubygem-newt-|^rubygem-oauth-|^rubygem-openscap-|^rubygem-powerbar-|^rubygem-rack-|^rubygem-rack-protection-|^rubygem-rake-|^rubygem-rb-inotify-|^rubygem-rest-client-|^rubygem-rkerberos-|^rubygem-rsec-|^rubygem-rubyipmi-|^rubygem-sinatra-|^rubygem-smart_proxy_ansible-|^rubygem-smart_proxy_discovery-|^rubygem-smart_proxy_openscap-|^rubygem-tilt-|^ruby-rgen-|^ruby-shadow-|^saslwrapper-|^SOAPpy-|^sshpass-|^tfm-ror52-rubygem-actioncable-|^tfm-ror52-rubygem-actionmailer-|^tfm-ror52-rubygem-actionpack-|^tfm-ror52-rubygem-actionview-|^tfm-ror52-rubygem-activejob-|^tfm-ror52-rubygem-activemodel-|^tfm-ror52-rubygem-activerecord-|^tfm-ror52-rubygem-activestorage-|^tfm-ror52-rubygem-activesupport-|^tfm-ror52-rubygem-arel-|^tfm-ror52-rubygem-builder-|^tfm-ror52-rubygem-coffee-rails-|^tfm-ror52-rubygem-coffee-script-|^tfm-ror52-rubygem-crass-|^tfm-ror52-rubygem-erubi-|^tfm-ror52-rubygem-execjs-|^tfm-ror52-rubygem-globalid-|^tfm-ror52-rubygem-i18n-|^tfm-ror52-rubygem-loofah-|^tfm-ror52-rubygem-mail-|^tfm-ror52-rubygem-marcel-|^tfm-ror52-rubygem-method_source-|^tfm-ror52-rubygem-mimemagic-|^tfm-ror52-rubygem-mime-types-|^tfm-ror52-rubygem-mini_mime-|^tfm-ror52-rubygem-mini_portile2-|^tfm-ror52-rubygem-multi_json-|^tfm-ror52-rubygem-mustermann-|^tfm-ror52-rubygem-nio4r-|^tfm-ror52-rubygem-nokogiri-|^tfm-ror52-rubygem-rack-|^tfm-ror52-rubygem-rack-test-|^tfm-ror52-rubygem-rails-|^tfm-ror52-rubygem-railties-|^tfm-ror52-rubygem-sinatra-|^tfm-ror52-rubygem-sprockets-|^tfm-ror52-rubygem-sqlite3-|^tfm-ror52-rubygem-thor-|^tfm-ror52-rubygem-thread_safe-|^tfm-ror52-rubygem-tilt-|^tfm-ror52-rubygem-turbolinks-|^tfm-ror52-rubygem-tzinfo-|^tfm-ror52-runtime-|^tfm-rubygem-activerecord-import-|^tfm-rubygem-addressable-|^tfm-rubygem-algebrick-|^tfm-rubygem-ancestry-|^tfm-rubygem-anemone-|^tfm-rubygem-ansi-|^tfm-rubygem-apipie-bindings-|^tfm-rubygem-apipie-params-|^tfm-rubygem-apipie-rails-|^tfm-rubygem-audited-|^tfm-rubygem-autoparse-|^tfm-rubygem-awesome_print-|^tfm-rubygem-bastion-|^tfm-rubygem-bcrypt-|^tfm-rubygem-bundler_ext-|^tfm-rubygem-clamp-|^tfm-rubygem-colorize-|^tfm-rubygem-concurrent-ruby-|^tfm-rubygem-css_parser-|^tfm-rubygem-daemons-|^tfm-rubygem-deacon-|^tfm-rubygem-declarative-|^tfm-rubygem-declarative-option-|^tfm-rubygem-deep_cloneable-|^tfm-rubygem-deface-|^tfm-rubygem-diffy-|^tfm-rubygem-docker-api-|^tfm-rubygem-domain_name-|^tfm-rubygem-ethon-|^tfm-rubygem-excon-|^tfm-rubygem-extlib-|^tfm-rubygem-facter-|^tfm-rubygem-faraday-|^tfm-rubygem-fast_gettext-|^tfm-rubygem-ffi-|^tfm-rubygem-fog-|^tfm-rubygem-fog-aws-|^tfm-rubygem-fog-core-|^tfm-rubygem-fog-digitalocean-|^tfm-rubygem-fog-google-|^tfm-rubygem-fog-json-|^tfm-rubygem-fog-kubevirt-|^tfm-rubygem-fog-libvirt-|^tfm-rubygem-fog-openstack-|^tfm-rubygem-fog-ovirt-|^tfm-rubygem-fog-rackspace-|^tfm-rubygem-fog-vsphere-|^tfm-rubygem-fog-xenserver-|^tfm-rubygem-fog-xml-|^tfm-rubygem-foreigner-|^tfm-rubygem-formatador-|^tfm-rubygem-friendly_id-|^tfm-rubygem-get_process_mem-|^tfm-rubygem-gettext-|^tfm-rubygem-gettext_i18n_rails-|^tfm-rubygem-git-|^tfm-rubygem-google-api-client-|^tfm-rubygem-googleauth-|^tfm-rubygem-graphql-|^tfm-rubygem-graphql-batch-|^tfm-rubygem-gssapi-|^tfm-rubygem-hammer_cli-|^tfm-rubygem-hammer_cli_csv-|^tfm-rubygem-hammer_cli_import-|^tfm-rubygem-hashie-|^tfm-rubygem-highline-|^tfm-rubygem-http-|^tfm-rubygem-httpclient-|^tfm-rubygem-http-cookie-|^tfm-rubygem-http-form_data-|^tfm-rubygem-http_parser-|^tfm-rubygem-i18n-|^tfm-rubygem-ipaddress-|^tfm-rubygem-jgrep-|^tfm-rubygem-journald-logger-|^tfm-rubygem-journald-native-|^tfm-rubygem-jquery-ui-rails-|^tfm-rubygem-jwt-|^tfm-rubygem-katello-|^tfm-rubygem-kubeclient-|^tfm-rubygem-launchy-|^tfm-rubygem-ldap_fluff-|^tfm-rubygem-little-plugger-|^tfm-rubygem-locale-|^tfm-rubygem-logging-|^tfm-rubygem-logging-journald-|^tfm-rubygem-memoist-|^tfm-rubygem-ms_rest-|^tfm-rubygem-multi_json-|^tfm-rubygem-multipart-post-|^tfm-rubygem-net-ldap-|^tfm-rubygem-net-ping-|^tfm-rubygem-netrc-|^tfm-rubygem-net-scp-|^tfm-rubygem-net-ssh-|^tfm-rubygem-net-ssh-krb-|^tfm-rubygem-nokogiri-|^tfm-rubygem-oauth-|^tfm-rubygem-optimist-|^tfm-rubygem-os-|^tfm-rubygem-ovirt-engine-sdk-|^tfm-rubygem-parse-cron-|^tfm-rubygem-pg-|^tfm-rubygem-polyglot-|^tfm-rubygem-powerbar-|^tfm-rubygem-prometheus-client-|^tfm-rubygem-promise-|^tfm-rubygem-public_suffix-|^tfm-rubygem-quantile-|^tfm-rubygem-rabl-|^tfm-rubygem-rack-cors-|^tfm-rubygem-rack-jsonp-|^tfm-rubygem-rails-i18n-|^tfm-rubygem-rails-observers-|^tfm-rubygem-rainbow-|^tfm-rubygem-rbovirt-|^tfm-rubygem-rbvmomi-|^tfm-rubygem-record_tag_helper-|^tfm-rubygem-redhat_access-|^tfm-rubygem-redhat_access_lib-|^tfm-rubygem-representable-|^tfm-rubygem-responders-|^tfm-rubygem-rest-client-|^tfm-rubygem-retriable-|^tfm-rubygem-roadie-|^tfm-rubygem-roadie-rails-|^tfm-rubygem-robotex-|^tfm-rubygem-ruby2ruby-|^tfm-rubygem-ruby-libvirt-|^tfm-rubygem-ruby_parser-|^tfm-rubygem-runcible-|^tfm-rubygem-safemode-|^tfm-rubygem-scoped_search-|^tfm-rubygem-secure_headers-|^tfm-rubygem-sequel-|^tfm-rubygem-sexp_processor-|^tfm-rubygem-signet-|^tfm-rubygem-sprockets-|^tfm-rubygem-sprockets-rails-|^tfm-rubygem-sshkey-|^tfm-rubygem-statsd-instrument-|^tfm-rubygem-table_print-|^tfm-rubygem-text-|^tfm-rubygem-timeliness-|^tfm-rubygem-trollop-|^tfm-rubygem-turbolinks-|^tfm-rubygem-typhoeus-|^tfm-rubygem-uber-|^tfm-rubygem-unf-|^tfm-rubygem-unf_ext-|^tfm-rubygem-unicode-|^tfm-rubygem-useragent-|^tfm-rubygem-webpack-rails-|^tfm-rubygem-wicked-|^tfm-rubygem-will_paginate-|^tfm-rubygem-x-editable-rails-|^tfm-rubygem-zest-|^tfm-runtime-"


report()
{

  # define variables to be used later

  base_dir=$1
  base_foreman=$base_dir/$2
  sos_version=$3

  HOSTNAME=""
  if [ -f "$base_dir/hostname" ]; then HOSTNAME=`cat $base_dir/hostname`; fi

  HOSTS_ENTRY=""
  if [ -f "$base_dir/etc/hosts" ] && [ "$HOSTNAME" ]; then HOSTS_ENTRY=`grep $HOSTNAME $base_dir/etc/hostsi | egrep --color=always '^|$IPADDRLIST'`; fi

  PRIMARYNIC=""
  if [ -f "$base_dir/route" ]; then PRIMARYNIC=`grep UG $base_dir/route | awk '{print $NF}'`; fi

  IPADDRLIST=""
  if [ -f "$base_dir/ip_addr" ]; then IPADDRLIST=`egrep "$PRIMARYNIC" $base_dir/ip_addr | egrep -v "inet6|: lo" | awk '{print $4}' | awk -F"/" '{print $1}' | tr '\n' '|' | rev | cut -c2- | rev`; fi


  log_tee "### Welcome to Report ###"
  log_tee "### CEE/SysMGMT ###"
  log_tee " "



  log_tee "## Date"
  log

  log "// date sosreport was collected"
  log "---"
  log_cmd "tail -1 $base_dir/date"
  log "---"
  log

  log "// hostname"
  log "---"
  log_cmd "cat $base_dir/hostname"
  log "---"
  log

  log "// facts stored in /var/lib/rhsm/facts/facts.json"
  log "jq '. | \"hostname: \" + .\"network.hostname\",\"FQDN: \" + .\"network.fqdn\"' $base_dir/var/lib/rhsm/facts/facts.json"
  log "---"
  log_cmd "jq '. | \"hostname: \" + .\"network.hostname\",\"FQDN: \" + .\"network.fqdn\"' $base_dir/var/lib/rhsm/facts/facts.json"
  log "---"
  log

  if [ "$HOSTS_ENTRY" ]; then
    log "// hostname in /etc/hosts"
    log "---"
    log "$HOSTS_ENTRY"
    log "---"
    log
  fi


  log_tee "## Case Summary"
  log

  log "// environment for case summary"
  log "---"
  log "ENVIRONMENT:"
  log
  log_cmd "egrep 'satellite-6|capsule-6|spacewalk|^rhui|^rh-rhua' $base_dir/installed-rpms | awk '{print \$1}'"
  log
  log_cmd "grep release $base_dir/installed-rpms | awk '{print \$1}' | egrep -i 'redhat|oracle|centos|suse|fedora' | egrep -v 'eula|base'"
  log
  log "HW platform:"
  log
  log_cmd "{ grep -E '(Vendor|Manufacture|Product Name:|Description:)' $base_dir/dmidecode | head -n3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; } || { grep virtual $base_dir/facts 2>/dev/null | egrep \"vendor|version|manufacturer|name\" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; }"
  log
  log "---"
  log



  log_tee "## Platform"
  log

  log "// operating system"
  log "---"
  log_cmd "cat $base_dir/etc/redhat-release 2>/dev/null || grep -A9 '^os =>' $base_dir/facts"
  log "---"
  log

  log "// release version (for version locking)"
  log "jq '.' $base_dir/var/lib/rhsm/cache/releasever.json"
  log "---"
  log_cmd "jq '.' $base_dir/var/lib/rhsm/cache/releasever.json"
  log "---"
  log

  log "// release packages"
  log "grep release $base_dir/installed-rpms | awk '{print $1}'"
  log "---"
  RELEASE_PACKAGE=`grep release $base_dir/installed-rpms | awk '{print $1}'`
  log "$RELEASE_PACKAGE"
  log "---"
  log

  log "// baremetal or vm?"
  log "grep dmidecode or facts files for vendor and manufacturer"
  log "---"
  log_cmd "{ grep -E '(Vendor|Manufacture|Product Name:|Description:)' $base_dir/dmidecode | head -n3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; } || { grep virtual $base_dir/facts 2>/dev/null | egrep \"vendor|version|manufacturer|name\" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; }"
  log "---"
  log

  log_tee "## Memory"
  log

  log "// memory usage"
  log "cat $base_dir/free"
  log "---"
  log_cmd "cat $base_dir/free"
  log " "
  memory_usage=$(cat $base_dir/ps | sort -nr | awk '{print $6}' | grep -v ^RSS | grep -v ^$ | paste -s -d+ | bc)
  memory_usage_gb=$(echo "scale=2;$memory_usage/1024/1024" | bc)
  log "Total Memory Consumed in GiB: $memory_usage_gb"
  log "---"
  log

  log "// xsos memory info"
  log "xsos --mem $base_dir"
  log "---"
  log_cmd "xsos --mem $base_dir"
  log "---"
  log


  log "// out of memory errors"
  log "grep \"Out of memory\" $base_dir/var/log/messages"
  log "---"
  log_cmd "grep \"Out of memory\" $base_dir/var/log/messages"
  log "---"
  log

  log "// custom hiera"
  log "cat $base_foreman/etc/foreman-installer/custom-hiera.yaml"
  log "---"
  log_cmd "cat $base_foreman/etc/foreman-installer/custom-hiera.yaml | egrep -v \"\#|---\""
  log "---"
  log

  log "// top 5 memory consumers by process"
  log "cat $base_dir/ps | sort -nrk6 | head -n5"
  log "---"
  log_cmd "cat $base_dir/ps | sort -nrk6 | head -n5"
  log "---"
  log

  log "// top memory consumers by user"
  log "from $base_dir/ps"
  log "---"
  log "Total Memory Consumed in KiB: $memory_usage"
  log "Total Memory Consumed in GiB: $memory_usage_gb"
  log
  log_cmd "cat $base_dir/ps | sort -nr | awk '{print \$1, \$6}' | grep -v ^USER | grep -v ^COMMAND | grep -v \"^ $\" | awk  '{a[\$1] += \$2} END{for (i in a) print i, a[i]}' | sort -nrk2"
  log "---"
  log




  log_tee "## Storage"
  log

  log "// disk usage info"
  log "awk '{ if (\$2!=0) print \$0 }' $base_dir/df"
  log "---"
  log_cmd "awk '{ if (\$2!=0) print \$0 }' $base_dir/df | egrep --color=always \"^|nfs\""
  log "---"
  log

  log "Note:  Putting /var/lib/pulp, /var/lib/mongodb or /var/lib/pgsql/ on nfs mounts can degrade the Satellite server's performance, so look for that."
  log

  log "// inode exhaustion info"
  log "awk '{ if (\$2!=0) print \$0 }' $base_dir/sos_commands/filesys/df_-ali_-x_autofs"
  log "---"
  log_cmd "awk '{ if (\$2!=0) print \$0 }' $base_dir/sos_commands/filesys/df_-ali_-x_autofs"
  log "---"
  log

  log "// logrotate entry for dynflow_executor.output"
  log "grep dynflow_executor.output $base_dir/etc/logrotate.d/foreman*"
  log "---"
  log_cmd "grep dynflow_executor.output $base_dir/etc/logrotate.d/foreman*"
  log "---"
  log

  log "// read-only volumes"
  log "egrep \"\/dev\/sd|\/dev\/mapper\" $base_dir/mount | grep -v rw"
  log "---"
  log_cmd "egrep \"\/dev\/sd|\/dev\/mapper\" $base_dir/mount | grep -v rw | egrep --color=always \"^|\/tmp\""
  log "---"

  log "Note:  The satellite-installer tool can fail when /tmp and/or /var/tmp are mounted read-only, so look for that."
  log

  log "// no space left on device"
  log "grep -h -r \"No space left on device\" $base_dir/* 2>/dev/null | egrep -v '{|}'"
  log "---"
  log_cmd "grep -h -r \"No space left on device\" $base_dir/* 2>/dev/null | egrep -v '{|}'"
  log "---"
  log


  log_tee "## Proxies"
  log

  log "// RHSM Proxy"
  log "grep proxy $base_dir/etc/rhsm/rhsm.conf | grep -v ^#"
  log "---"
  log_cmd "grep proxy $base_dir/etc/rhsm/rhsm.conf | grep -v ^#"
  log "---"
  log

  log "// yum Proxy"
  log "grep proxy $base_dir/etc/yum.conf | grep -v ^#"
  log "---"
  log_cmd "grep proxy $base_dir/etc/yum.conf | grep -v ^#"
  log "---"
  log

  log "// Satellite Proxy"
  log "from file /etc/foreman-installer/scenarios.d/satellite-answers.yaml"
  log "---"
  log_cmd "grep -E '(^  proxy_url|^  proxy_port|^  proxy_username|^  proxy_password)' $base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml"
  log "---"
  log

  log "// Virt-who Proxy"
  log "grep -i proxy $base_dir/etc/sysconfig/virt-who"
  log "---"
  log_cmd "grep -i proxy $base_dir/etc/sysconfig/virt-who"
  log "---"
  log


  log_tee "## Network Information"
  log

  log "// ip address"
  log "cat $base_dir/ip_addr"
  log "---"
  log_cmd "cat $base_dir/ip_addr"
  log "---"
  log

  #log "// ip address stored in /var/lib/rhsm/facts/facts.json"
  #log "jq '. | \"IP address: \" + .\"network.ipv4_address\"' $base_dir/var/lib/rhsm/facts/facts.json"
  #log "---"
  #log_cmd "jq '. | \"IP address: \" + .\"network.ipv4_address\"' $base_dir/var/lib/rhsm/facts/facts.json"
  #log "---"
  #log

  if [ -f "$base_dir/ping_hostname" ] || [ -f "$base_dir/ping_hostname_full" ]; then
	log "// ping hostname"
	log "---"
	log "cat $base_dir/ping_hostname"
	log
	log "// ping full hostname"
	log "cat $base_dir/ping_hostname_full"
	log "---"
	log
  fi

  log "// hosts entries"
  log "cat $base_dir/etc/hosts"
  log "---"
  export GREP_COLORS='ms=01;33'
  log_cmd "cat $base_dir/etc/hosts | egrep --color=always '^|$HOSTNAME|$IPADDRLIST'"
  export GREP_COLORS='ms=01;31'
  log "---"
  log

  log "// resolv.conf"
  log "cat $base_dir/etc/resolv.conf"
  log "---"
  log_cmd "cat $base_dir/etc/resolv.conf"
  log "---"
  log

  log "// firewalld settings"
  log "egrep -A14 \"(active)|^FirewallD is not running\" $base_dir/sos_commands/firewalld/firewall-cmd_--list-all-zones"
  log "---"
  log_cmd "egrep -A14 \"(active)|^FirewallD is not running\" $base_dir/sos_commands/firewalld/firewall-cmd_--list-all-zones"
  log "---"
  log

  log "// iptables extra line count"
  log "egrep -v \"^$|^COMMAND|Chain|pkts\" $base_dir/sos_commands/networking/iptables_-vnxL | wc -l"
  log "---"
  log_cmd "egrep -v \"^$|^COMMAND|Chain|pkts\" $base_dir/sos_commands/networking/iptables_-vnxL | wc -l"
  log "---"
  log

  log "Note:  If firewalld is running, then the iptables output should contain rules (roughly 30-40 on a Satellite 6.7 server).  If firewalld is not running and iptables still has rules defined, then the customer is likely using hand-crafted rules."

  log

  log "// current route"
  log "cat $base_dir/route"
  log "---"
  log_cmd "cat $base_dir/route"
  log "---"
  log

  log_tee "## Environment"

  log "// LANG and PATH
  log "egrep 'LANG|PATH' $base_dir/sos_commands/systemd/systemctl_show-environment"
  log
  log_cmd "egrep 'LANG|PATH' $base_dir/sos_commands/systemd/systemctl_show-environment"
  log

  log "// contents of /etc/environment
  log "cat $base_dir/etc/environment"
  log
  log_cmd "cat $base_dir/etc/environment"
  log

  #if [ -f "$base_dir/facts" ]; then
	#log "grep path $base_dir/facts"
	#log "---"
	#log_cmd "grep path $base_dir/facts"
	#log "---"
  #fi

  log_tee "## SELinux"
  log

  log "// SELinux conf"
  log "display SELinux settings"
  log "---"
  log_cmd "grep -v \# $base_dir/etc/selinux/config | grep ."
  log "---"
  log

  log "// setroubleshoot package"
  log "grep setroubleshoot $base_dir/installed-rpms"
  log "---"
  log_cmd "grep setroubleshoot $base_dir/installed-rpms"
  log "---"
  log

  log "// SELinux denials"
  log "grep for selinux denials"
  log "---"
  log_cmd "tail -30 $base_dir/selinux_denials.log 2>/dev/null || grep -o denied.* $base_dir/var/log/audit/audit.log | sort -u | tail -100"
  log "---"
  log

  if [ -f "$base_dir/foreman_filecontexts" ]; then
	log "// foreman file contexts"
	log "cat $base_dir/foreman_filecontexts"
	log "---"
	log_cmd "cat $base_dir/foreman_filecontexts"
	log "---"
	log
  fi

  log_tee "## cron"
  log

  log "// crontabs in /var/spool/cron"
  log "ls -l $base_dir/var/spool/cron/*"
  log "---"
  log_cmd "ls -l $base_dir/var/spool/cron/* 2>/dev/null || echo 'No cron files found in /var/spool/cron'"
  log "---"
  log

  log "// checking the contents of crontabs in /var/spool/cron"
  log "for b in \$(ls -1 $base_dir/var/spool/cron/*); do echo; echo \$b; echo \"===\"; cat \$b; echo \"===\"; done"
  log "---"
  log_cmd "for b in $(ls -1 $base_dir/var/spool/cron/* 2>/dev/null); do echo; echo \$b; echo \"===\"; cat \$b; echo \"===\"; done"
  log "---"
  log

  log "// custom cron files in /etc"
  log "---"
  log_cmd "find $base_dir/etc/cron* -type f | awk 'FS=\"/etc/\" {print \$2}' | egrep -v 'cron.d\/foreman$|cron.d\/rubygem-smart_proxy_openscap$|cron.daily\/logrotate$|cron.daily\/rhsmd$|cron.daily\/man-db.cron$|cron.daily\/katello-repository-publish-check$|cron.deny$|cron.hourly\/0anacron$|crontab$|cron.weekly\/katello-clean-empty-puppet-environments$|cron.weekly\/katello-remove-orphans$|cron.d\/katello$|cron.d\/foreman-tasks$|cron.daily\/mlocate$|cron.weekly\/pulp-maintenance$|cron.d\/0hourly$|cron.daily\/rhsmd$|cron.allow$|cron.d\/raid-check$|cron.d\/sysstat$|cron.daily\/schema-upgrade-notif$|cron.daily\/makewhatis.cron$|cron.daily\/certwatch$|cron.daily\/cups$|cron.daily\/check-database-space-usage.sh$|cron.daily\/prelink$|cron.daily\/mlocate.cron$|cron.daily\/tmpwatch$|cron.daily\/rhn-ssl-cert-check$|cron.daily\/readahead.cron$|cron.hourly\/mcelog.cron$|cron.monthly\/readahead-monthly.cron$|cron.d\/katello-host-tools$|cron.daily\/rpm$|cron.daily\/rhsmd$' | grep ."
  log "---"
  log

  log "// standard Satellite 6 cron files in /etc"
  log "---"
  export GREP_COLORS='ms=01;33'
  log_cmd "find $base_dir/etc/cron* -type f | awk 'FS=\"/etc/\" {print \$2}' | egrep 'cron.d\/foreman$|cron.d\/rubygem-smart_proxy_openscap$|cron.daily\/logrotate$|cron.daily\/rhsmd$|cron.daily\/man-db.cron$|cron.daily\/katello-repository-publish-check$|cron.deny$|cron.hourly\/0anacron$|crontab$|cron.weekly\/katello-clean-empty-puppet-environments$|cron.weekly\/katello-remove-orphans$|cron.d\/katello$|cron.d\/foreman-tasks$|cron.daily\/mlocate$|cron.weekly\/pulp-maintenance$|cron.d\/0hourly$|cron.daily\/rhsmd$|cron.allow$|cron.d\/katello-host-tools' | grep . | egrep --color=always '^|foreman-tasks$'"
  export GREP_COLORS='ms=01;31'
  log "---"
  log

  log "// standard Satellite 5 cron files in /etc"
  log "---"
  export GREP_COLORS='ms=01;33'
  log_cmd "find $base_dir/etc/cron* -type f | awk 'FS=\"/etc/\" {print \$2}' | egrep 'cron.d\/raid-check$|cron.d\/sysstat$|cron.daily\/schema-upgrade-notif$|cron.daily\/makewhatis.cron$|cron.daily\/certwatch$|cron.daily\/cups$|cron.daily\/check-database-space-usage.sh$|cron.daily\/prelink$|cron.daily\/mlocate.cron$|cron.daily\/tmpwatch$|cron.daily\/rhn-ssl-cert-check$|cron.daily\/readahead.cron$|cron.hourly\/mcelog.cron$|cron.monthly\/readahead-monthly.cron$|cron.daily\/rpm$|cron.daily\/rhsmd$' | grep . | egrep --color=always '^|foreman-tasks$'"
  export GREP_COLORS='ms=01;31'
  log "---"
  log

  log "// last 20 entries from foreman/cron.log"
  log "tail -20 $base_foreman/var/log/foreman/cron.log"
  log "---"
  log_cmd "tail -20 $base_foreman/var/log/foreman/cron.log | tail -100"
  log "---"
  log

  log_tee "## /var/log/messages"
  log

  log "// error on messages file"
  log "grep messages files for errors"
  log "---"
  { for mylog in `ls -rt $base_dir/var/log/messages* 2>/dev/null`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | tail -200 &>> $FOREMAN_REPORT
  log "---"
  log


  log_tee " "
  log


  log_tee "## Repos and Packages"
  log

  log "// enabled repos"
  log "cat $base_dir/sos_commands/yum/yum_-C_repolist"
  log "---"
  log_cmd "cat $base_dir/sos_commands/yum/yum_-C_repolist | egrep -i --color=always \"^|epel|fedora\""
  log "---"
  log

  log "// all installed satellite packages"
  log "egrep \"satellite|spacewalk|spacecmd\" $base_dir/installed-rpms"
  log "---"
  log_cmd "egrep \"satellite|spacewalk|spacecmd\" $base_dir/installed-rpms"
  log "---"
  log

  log "// packages provided by 3rd party vendors"

  log "grep -v \"Red Hat\" $base_dir/sos_commands/rpm/package-data | cut -f1,4 | sort -k2"
  log "---"
  log_cmd "grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | cut -f1,4 | sort -k2 | egrep -i --color=always \"^|$SATPACKAGES\""
  log "---"
  log

  log "Note:  Third party packages sometimes cause issues for Satellite servers.  The EPEL repositories are known to have newer versions of some Satellite packages (which will be signed in the above list by \"Fedora\"), as is the upstream Foreman project (which will be signed by \"Koji\").  Antivirus scanners can sometimes prevent RPM installations, causing satellite-installer to fail."

  log


  log "// yum history"
  log "cat $base_dir/sos_commands/yum/yum_history"
  log "---"
  log_cmd "cat $base_dir/sos_commands/yum/yum_history | egrep -i --color=always \"^|$SATPACKAGES\""
  log "---"
  log

  log "// yum.log info"
  log "cat $base_dir/var/log/yum.log"
  log "---"
  log_cmd "cat $base_dir/var/log/yum.log | egrep -i --color=always \"^|$SATPACKAGES\""
  log "---"
  log

  log_tee "## Satellite Upgrade"
  log

  log "// Recent exit codes from satellite-installer"

  log "grepping satellite and capsule files in foreman-maintain and foreman-installer directories for \"Exit with status code|--upgrade|Upgrade completed|Running installer with args\""
  log "---"

  export GREP_COLORS='ms=01;33'
  cmd_output=`egrep -i "Exit with status code|--upgrade|Upgrade completed|Running installer with args|ASCII" $base_dir/var/log/foreman-installer/{satellite*,capsule*} $base_dir/var/log/foreman-maintain/{satellite*,capsule*,foreman-maintain*} $base_dir/sos_commands/foreman/foreman-debug/var/log/foreman-installer/{satellite*,capsule*} $base_dir/sos_commands/foreman/foreman-debug/var/log/foreman-maintain/{satellite*,capsule*} $base_dir/var/log/katello-installer/* 2>/dev/null | egrep -v "Hook" | sed s'/\[\[//'g | awk -F"[" '{print $2}' | sort -k 2 | tail | egrep --color=always "^|tuning|upgrade"`

  log "$cmd_output"
  export GREP_COLORS='ms=01;31'

  log "---"
  log

  log "Note:  Exit codes of 0 indicate success, and exit codes of 2 indicate success accompanied by changes to Satellite."
  log

  log "// Number of errors in the upgrade logs"
  log "---"
  log_cmd "grep '^\[ERROR' $base_foreman/var/log/foreman-installer/satellite.log | wc -l"
  log "---"
  log

  log "// Last 20 lines from upgrade log"
  log "egrep -v \"\/opt|\]$|\.rb\:\" $base_foreman/var/log/foreman-installer/satellite.log | tail -20"
  log "---"
  log_cmd "egrep -v -v "\/opt|\]$|\.rb\:" $base_foreman/var/log/foreman-installer/satellite.log | tail -20"
  log "---"
  log


  log_tee "## Subscriptions"
  log

  log "// subscription identity"
  log "cat $base_dir/sos_commands/subscription_manager/subscription-manager_identity"
  log "---"
  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_identity"
  log "---"
  log

  log "// list rhsm target"
  log "egrep \"baseurl\|\^hostname\" $base_dir/etc/rhsm/rhsm.conf"
  log "---"
  log_cmd "egrep \"baseurl|^hostname\" $base_dir/etc/rhsm/rhsm.conf"
  log "---"
  log

  log "// subsman list installed"
  log "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--installed"
  log "---"
  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--installed"
  log "---"
  log

  log "// subsman list consumed"
  log "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
  log "---"
  log


  log_tee "## /var/log/rhsm/rhsm.log"
  log

  log "// RHSM errors"
  log "grep ERROR $base_dir/var/log/rhsm/rhsm.log"
  log "---"
  log_cmd "grep ERROR $base_dir/var/log/rhsm/rhsm.log | grep -v virt-who | tail -100"
  log "---"
  log

  log "// RHSM Warnings"
  log "grep WARNING $base_dir/var/log/rhsm/rhsm.log"
  log "---"
  log_cmd "grep WARNING $base_dir/var/log/rhsm/rhsm.log | egrep -v 'virt-who|logging already initialized' | tail -100"
  log "---"
  log

  log_tee " "
  log

  log_cmd "echo ================================================ | grep --color=always \="
  log
  log "Satellite Components"
  log
  log_cmd "echo ================================================ | grep --color=always \="
  log


  log "httpd                            qdrouterd"
  log "  |                                  |"
  log "  |      celery     mongodb       qpidd"
  log "  |           |          |           |"
  log "  \-pulp -----/----------/-----------/"
  log "  |"
  log "  \-passenger"
  log "        |"
  log "        \-puppet       postgreSQL                 tomcat"
  log "        |                |   |                       |"
  log "        \-foreman -------/   \---------candlepin-----/"
  log "            |"
  log "            \-katello, dynflow, virt-who, subscription watch"
  log
  log


  log_tee "## Satellite Services"
  log

  log "// hammer ping output"
  log "cat $base_dir/sos_commands/foreman/hammer_ping"
  log "---"
  log_cmd "cat $base_dir/sos_commands/foreman/hammer_ping | egrep --color=always \"^|FAIL|\[OK\]\""
  log "---"
  log

  log "// condensed satellite service status"
  log "grepping files foreman-maintain_service_status and systemctl_list-units"
  log "---"
  log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep --color=always '^|failed|inactive|activating|deactivating|\[OK\]'"
  log
  log_cmd "egrep 'puppet|virt-who' $base_dir/sos_commands/systemd/systemctl_list-units | egrep --color=always '^|failed|inactive|activating|deactivating'"
  log "---"
  log

  log "// satellite service status"
  log "from file $base_dir/sos_commands/foreman/foreman-maintain_service_status"
  log "---"
  export GREP_COLORS='ms=01;33'
  log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep --color=always \"^|Active:|\[OK\]|All services are running\" | egrep -v '{|}|displaying|^\||^\/|^\\|^\-'"
  export GREP_COLORS='ms=01;31'
  log "---"
  log

  log_tee " "
  log



  if [ ! "`egrep -i 'gofer|katello-agent' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps $base_dir/var/log/messages* 2>/dev/null | head -1`" ]; then

	nop=1

  else

	log_tee "## goferd"
	log

	log "// goferd service"
	log "from file $base_dir/sos_commands/systemd/systemctl_list-units"
	log "---"
	log_cmd "grep goferd $base_dir/sos_commands/systemd/systemctl_list-units"
	log "---"
	log

	log "// installed katello-agent and/or gofer"
	log "from file $base_dir/installed-rpms"
	log "---"
	log_cmd "grep -E '(^katello-agent|^gofer)' $base_dir/installed-rpms"
	log "---"
	log

  fi



  log_tee "## PostgreSQL"
  log

  if [ ! "`egrep -i 'postgres' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_foreman/var/lib/pgsql" ] && [ ! -d "$base_foreman/var/opt/rh/rh-postgresql12" ] && [ ! -d "$base_dir/sos_commands/postgresql" ]; then

	log "postgres not found"
	log

  else

    log "PostgreSQL is used by Foreman and Candlepin to store records related to registered content hosts, subscriptions, jobs, and tasks. Over time, PostgreSQL accumulates enough data to cause queries to slow relative to the speeds achievable in a fresh installation."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for postgresql"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'postgresql.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// Current Configuration"
	log "grep -v # $base_foreman/var/lib/pgsql/data/postgresql.conf $base_foreman/var/opt/rh/rh-postgresql12/data/postgresql.conf | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
	log "---"
	log_cmd "grep -v # $base_foreman/var/lib/pgsql/data/postgresql.conf $base_foreman/var/opt/rh/rh-postgresql12/data/postgresql.conf | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
	log "---"
	log

	log "// postgres configuration"
	log "grep 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target' $base_dir/var/lib/pgsql/data/postgresql.conf $base_foreman/var/opt/rh/rh-postgresql12/data/postgresql.conf | grep -v '^#'"
	log "---"
	log_cmd "grep 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target' $base_dir/var/lib/pgsql/data/postgresql.conf $base_foreman/var/opt/rh/rh-postgresql12/data/postgresql.conf | grep -v '^#'"
	log "---"
	log

	log "// postgres storage consumption"
	log "cat $base_dir/sos_commands/postgresql/du_-sh_.var.lib.pgsql"
	log "---"
	log_cmd "cat $base_dir/sos_commands/postgresql/du_-sh_.var.lib.pgsql"
	log "---"
	log

	log "// top foreman tables consumption"
	log "head -n30 $base_dir/sos_commands/katello/db_table_size"
	log "---"
	log_cmd "head -n30 $base_dir/sos_commands/katello/db_table_size"
	log "---"
	log

	log "// postgres idle process (everything)"
	log "grep ^postgres $base_dir/ps | grep idle$ | wc -l"
	log "---"
	log_cmd "grep ^postgres $base_dir/ps | grep idle$ | wc -l"
	log "---"
	log

	log "// deadlock count"
	log "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
	log "---"
	log_cmd "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
	log "---"
	log

	log "// deadlock"
	log "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log"
	log "---"
	log_cmd "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log | tail -100"
	log "---"
	log

	log "// ERROR count"
	log "grep ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
	log "---"
	log_cmd "grep ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
	log "---"
	log

	log "// ERROR"
	log "grep -h ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log"
	log "---"
	log_cmd "grep -h ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | tail -100"
	log "---"
	log

  fi

  log_tee "## MongoDB"
  log

  if [ ! "`egrep -i 'mongodb' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/etc/mongodb" ] && [ ! -d "$base_dir/var/log/mongodb" ]; then

	log "mongodb not found"
	log

  else

    log "MongoDB is a NoSQL database server which is used by Pulp to store the metadata related to the synchronized repositories and their contents. Pulp also uses MongoDB to store information about Pulp tasks and their current state."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for mongodb service"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A1 'mongod.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// mongodb memory consumption"
	log "from $base_dir/ps"
	log "---"
	log_cmd "grep -i mongo $base_dir/ps | sort -nr | awk '{print \$1, \$6}' | grep -v ^USER | grep -v ^COMMAND | grep -v \"^ $\" | awk  '{a[\$1] += \$2} END{for (i in a) print i, a[i]}' | sort -nrk2"
	log "---"
	log

	log "// cacheSize setting in custom hiera file"
	log "egrep 'mongodb::server::config_data|cacheSizeGB' $base_dir/etc/foreman-installer/custom-hiera.yaml"
	log "---"
	log_cmd "egrep '/var/log/messages::config_data|cacheSizeGB' $base_dir/etc/foreman-installer/custom-hiera.yaml"
	log "---"
	log


	  if [ -f "$base_dir/sos_commands/foreman/foreman-debug/mongodb_disk_space" ]; then
		  log "// mongodb storage consumption"
		  log "cat $base_dir/sos_commands/foreman/foreman-debug/mongodb_disk_space"
		  log "---"
		  log_cmd "cat $base_dir/sos_commands/foreman/foreman-debug/mongodb_disk_space"
		  log "---"
		  log
	  fi


  fi




  log_tee "## httpd (Apache)"
  log

  if [ ! "`egrep -i 'httpd' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/httpd" ]; then

	log "httpd not found"
	log

  else

    log "The Apache HTTP Server is a core component of Satellite. Passenger and Pulp, which are core components of Satellite, depend upon Apache HTTP Server to serve incoming requests. Requests that arrive through the web UI or the Satellite API are received by Apache HTTP Server and then forwarded to the components of Satellite that operate on them."
    log

	log "// service status"
	log "egrep -A2 \"httpd.service -\" $base_dir/sos_commands/foreman/foreman-maintain_service_status"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'httpd.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// queues on error_log means the # of requests crossed the border. Satellite inaccessible"
	log "grep 'Request queue is full' $base_foreman/var/log/httpd/error_log | wc -l"
	log "---"
	log_cmd "grep 'Request queue is full' $base_foreman/var/log/httpd/error_log | wc -l"
	log "---"
	log

	log "// when finding something on last step, we will here per date"
	log "grep queue $base_foreman/var/log/httpd/error_log  | awk '{print \$2, \$3}' | cut -d: -f1,2 | uniq -c"
	log "---"
	log_cmd "grep queue $base_foreman/var/log/httpd/error_log  | awk '{print \$2, \$3}' | cut -d: -f1,2 | uniq -c"
	log "---"
	log

	log "// TOP 20 of ip address requesting the satellite via https"
	log "awk '{print \$1}' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | sort | uniq -c | sort -nr | head -n20"
	log "---"
	log_cmd "awk '{print \$1}' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | sort | uniq -c | sort -nr | head -n20 | egrep --color=always \"^|$SATELLITE_IP\""
	log "---"
	log

	log "// TOP 20 of ip address requesting the satellite via https (detailed) - not from Satellite server"
	log "egrep -v \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1,\$4}' | cut -d: -f1,2,3 | uniq -c | sort -nr | head -n20"
	log "---"
	log_cmd "egrep -v \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1,\$4}' | cut -d: -f1,2,3 | uniq -c | sort -nr | head -n20"
	log "---"
	log

	log "// TOP 50 of uri requesting the satellite via https - not from Satellite server"
	log "egrep -v \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -n 50"
	log "---"
	log_cmd "egrep -v \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -n 50"
	log "---"
	log

	log "// TOP 50 of uri requesting the satellite via https - from Satellite server"
	log "egrep \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -n 50"
	log "---"
	log_cmd "egrep \"$HOST_IPS\" $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -n 50"
	log "---"
	log



	log "// General HTTP return codes in apache logs"

	log "\$n;grep -P '\" \$n\d\d ' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
	log "---"
	log_cmd "grep -P '\" 2\d\d ' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
	log
	log_cmd "grep -P '\" 3\d\d ' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
	log
	log_cmd "grep -P '\" 4\d\d ' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
	log
	log_cmd "grep -P '\" 5\d\d ' $base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
	log "---"
	log

	log "// sysctl configuration"
	log "grep 'fs.aio-max-nr' $base_dir/etc/sysctl.conf"
	log "---"
	log_cmd "grep 'fs.aio-max-nr' $base_dir/etc/sysctl.conf"
	log "---"
	log

	log "// httpd|apache limits"
	log "grep LimitNOFILE $base_dir/etc/systemd/system/httpd.service.d/limits.conf"
	log "---"
	log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/httpd.service.d/limits.conf"
	log "---"
	log


	log "// prefork.conf configuration"
	log "egrep 'ServerLimit|StartServers' $base_dir/etc/httpd/conf.modules.d/prefork.conf"
	log "---"
	log_cmd "egrep 'ServerLimit|StartServers' $base_dir/etc/httpd/conf.modules.d/prefork.conf"
	log "---"
	log

  fi


  log_tee "## Passenger"
  log

  if [ ! "`egrep -i passenger $base_dir/sos_commands/foreman/passenger-status_--show_pool $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf $base_dir/etc/httpd/conf.d/passenger.conf 2>/dev/null | head -1`" ]; then

	log "passenger not found"
	log

  else

    log "Passenger is a web server and a core component of Red Hat Satellite. Satellite uses Passenger to run Ruby applications such as Foreman and Puppet. Passenger integrates with Apache HTTP Server to capture incoming requests and redirects them to the respective components that handle them."
    log

    log "Passenger is involved in Satellite when the GUI is accessed, when the APIs are accessed, and when content hosts are registered. Each request that is serviced by Passenger consumes an Apache HTTP Server process. Passenger queues requests into an application-specific wait queue. The maximum number of requests that can be queued by Passenger is defined in the Passenger configuration. When running at scale, it might be desirable to increase the number of requests that Passenger can handle concurrently. It might also be desirable to increase the size of the wait queue to accommodate bursts of requests."
    log

    log "Passenger is configured within the Apache HTTP Server configuration files. It can be used to control the performance, scaling, and behavior of Foreman and Puppet."
    log

	  if [ "`grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | grep passenger`" ]; then
		log "// 3rd party passenger packages"
		log "from file $base_dir/sos_commands/rpm/package-data"
		log "---"
		log_cmd "grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | grep passenger | cut -f1,4 | sort -k2"
		log "---"
		log
	  fi

	log "// current passenger status"
	log "cat $base_dir/sos_commands/foreman/passenger-status_--show_pool"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/passenger-status_--show_pool"
	log "---"
	log

	log "// total # of foreman tasks"
	log "cat $base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
	log "---"
	log

	log "// max_pool_size in custom hiera"
	log "grep passenger_max_pool_size $foreman_dir/etc/foreman-installer/custom-hiera.yaml $base_dir/etc/foreman-installer/custom-hiera.yaml"
	log "---"
	log_cmd "grep passenger_max_pool_size $foreman_dir/etc/foreman-installer/custom-hiera.yaml $base_dir/etc/foreman-installer/custom-hiera.yaml"
	log "---"
	log

	log "// passenger.conf configuration - 6.3 or less"
	log "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.d/passenger.conf"
	log "---"
	log_cmd "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.d/passenger.conf"
	log "---"
	log

	log "// passenger-extra.conf configuration - 6.4+"
	log "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf"
	log "---"
	log_cmd "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf"
	log "---"
	log

	log "// 05-foreman.conf configuration"
	log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman.conf"
	log "---"
	log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman.conf"
	log "---"
	log

	log "// 05-foreman-ssl.conf configuration"
	log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman-ssl.conf"
	log "---"
	log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman-ssl.conf"
	log "---"
	log


	log "// URI requests"
	log "grep uri $base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests | sort -k3 | uniq -c"
	log "---"
	log_cmd "grep uri $base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests | sort -k3 | uniq -c"
	log "---"
	log

  fi



  log_tee "## Puppet Server"
  log

  if [ ! "`egrep -i 'puppet' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/puppetlabs" ] && [ ! -d "$base_dir/var/log/puppet" ] && [ ! -d "$base_dir/etc/puppet" ] && [ ! -d "$base_dir/etc/puppetlabs" ]; then

	log "puppet not found"
	log

  else

    log "Puppet 3 is a Ruby application and runs inside the Passenger application server. Puppet 4 runs as a standalone, Java-based application."
    log

	log "// service status"
	log "grep systemctl_list-units for puppet services"
	log "---"
	log_cmd "grep puppet $base_dir/sos_commands/systemd/systemctl_list-units | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// Puppet Server Error"
	log "grep ERROR $base_dir/var/log/puppetlabs/puppetserver/puppetserver.log $base_dir/var/log/puppet/puppetserver/puppetserver.log 2>/dev/null"
	log "---"
	log_cmd "grep ERROR $base_dir/var/log/puppetlabs/puppetserver/puppetserver.log $base_dir/var/log/puppet/puppetserver/puppetserver.log 2>/dev/null | tail -100"
	log "---"
	log

  fi


  log_tee "## Foreman"
  log

  if [ ! "`egrep -i foreman $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps $base_foreman/var/log/foreman/production.log* 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/foreman-proxy" ] && [ ! -d "$base_dir/var/log/foreman" ] && [ ! -d "$base_dir/var/log/foreman-installer" ] && [ ! -d "$base_dir/var/log/foreman-maintain" ] && [ ! -d "$base_dir/var/log/katello-installer" ]; then

	log "foreman not found"
	log

  else

    log "Foreman is a Ruby application that runs inside the Passenger application server and does a number of things, among them providing a UI, providing remote execution, running Foreman SCAP scans on content hosts. Foreman is also involved in Content Host Registrations.  Foreman’s performance and scalability are affected directly by the configurations of httpd and Passenger."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for foreman services"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'foreman-proxy.service -|foreman-tasks.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log


	log "// foreman tasks cleanup script"
	log "cat $base_dir/etc/cron.d/foreman-tasks"
	log "---"
	log_cmd "cat $base_dir/etc/cron.d/foreman-tasks"
	log "---"
	log


	log "// paused foreman tasks"
	log "grepping foreman_tasks_tasks for paused tasks"
	log "---"
	log_cmd "grep -E '(^                  id|paused)' $base_dir/sos_commands/foreman/foreman_tasks_tasks | sed 's/  //g' | sed -e 's/ |/|/g' | sed -e 's/| /|/g' | sed -e 's/^ //g' | sed -e 's/|/,/g'"
	log "---"
	log

	log "// foreman settings"
	log "cat $base_foreman/etc/foreman/settings.yaml"
	log "---"
	log_cmd "cat $base_foreman/etc/foreman/settings.yaml"
	log "---"
	log

	log "// postgres idle processes (foreman)"
	log "grep ^postgres $base_dir/ps | grep idle$ | grep \"foreman foreman\" | wc -l"
	log "---"
	log_cmd "grep ^postgres $base_dir/ps | grep idle$ | grep \"foreman foreman\" | wc -l"
	log "---"
	log

	log "// Tasks TOP"
	log "grep Actions $base_dir/sos_commands/foreman/foreman_tasks_tasks  | cut -d, -f3 | sort | uniq -c | sort -nr | tail -100"
	log "---"
	log_cmd "grep Actions $base_dir/sos_commands/foreman/foreman_tasks_tasks  | cut -d, -f3 | sort | uniq -c | sort -nr | tail -100"
	log "---"
	log

	log "// total number of errors found on production.log - TOP 40"
	log "grep -h \"\[E\" $base_foreman/var/log/foreman/production.log* | awk '{print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$13}' | sort | uniq -c | sort -nr | head -n40"
	log "---"
	log_cmd "grep -h \"\[E\" $base_foreman/var/log/foreman/production.log* | awk '{print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$13}' | sort | uniq -c | sort -nr | head -n40"
	log "---"
	log

  fi


  log_tee "## Katello"
  log

  if [ ! -f "$base_dir/sos_commands/katello/qpid-stat_-q*" ] && [ ! -f "$base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf" ]; then

	log "katello server not found"
	log

  else

    log "Katello is a Foreman plug-in for subscription and repository management. It provides a means to subscribe to Red Hat repositories and download content. You can create and manage different versions of this content and apply them to specific systems within user-defined stages of the application life cycle."
    log

	log "// katello_event_queue (foreman-tasks / dynflow is running?)"
	log "grep -E '(  queue|  ===|katello_event_queue)' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671"
	log "---"
	log_cmd "grep -E '(  queue|  ===|katello_event_queue)' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671"
	log "---"
	log

	log "// katello.conf configuration"
	log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout $base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf'"
	log "---"
	log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout $base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf'"
	log "---"
	log

  fi


  log_tee "## Dynflow"
  log

  if [ ! "`egrep -i dynflow $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps $base_dir/sos_commands/foreman/foreman_tasks_tasks 2>/dev/null | head -1`" ] && [ ! -f "$base_dir/etc/sysconfig/dynflowd" ]; then

	log "dynflow not found"
	log

  else

    log "DynFlow is a workflow system and task orchestration engine written in Ruby, and runs as a plugin to Foreman. Foreman uses DynFlow to schedule, plan, and execute queued tasks."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for smart_proxy_dynflow_core"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'smart_proxy_dynflow_core.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// number of running dynflow executors"
	log "grep dynflow_executor\$ $base_dir/ps"
	log "---"
	log_cmd "grep dynflow_executor\$ $base_dir/ps"
	log "---"
	log

	log "// dynflow optimizations - 6.3 or less"
	log "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/foreman-tasks"
	log "---"
	log_cmd "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/foreman-tasks"
	log "---"
	log

	log "// dynflow optimizations - 6.4 or greater"
	log "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/dynflowd"
	log "---"
	log_cmd "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/dynflowd"
	log "---"
	log

	log "// smart proxy dynflow core limits"
	log "grep LimitNOFILE $base_dir/etc/systemd/system/smart_proxy_dynflow_core.service.d/90-limits.conf"
	log "---"
	log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/smart_proxy_dynflow_core.service.d/90-limits.conf"
	log "---"
	log

	log "// foreman-tasks/dynflow configuration - 6.3 or less"
	log "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' $base_dir/etc/sysconfig/foreman-tasks"
	log "---"
	log_cmd "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' $base_dir/etc/sysconfig/foreman-tasks"
	log "---"
	log

	log "// foreman-tasks/dynflow configuration - 6.4+"
	log "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' $base_dir/etc/sysconfig/dynflowd"
	log "---"
	log_cmd "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' $base_dir/etc/sysconfig/dynflowd"
	log "---"
	log

	log "Notes:"
	log "    EXECUTOR_MEMORY_LIMIT defines the amount of memory that a single dynFlow executor process can consume before the executor is recycled."
	log
	log "    EXECUTOR_MEMORY_MONITOR_DELAY defines when the first polling attempt to check the executor memory is made after the initialization of the executor."
	log
	log "    EXECUTOR_MEMORY_MONITOR_INTERVAL defines how frequently the memory usage of executor is polled."
	log

  fi


  log_tee "## Pulp"
  log

  if [ ! "`egrep -i pulp $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

	log "pulp not found"
	log

	log "// number of CPUs"
	log "grep processor $base_dir/proc/cpuinfo | wc -l"
	log "---"
	log_cmd "grep processor $base_dir/proc/cpuinfo | wc -l"
	log "---"
	log

	log "// number of sockets"
	log "grep 'Socket.Designation:' $base_dir/dmidecode | wc -l"
	log "---"
	log_cmd "grep 'Socket.Designation:' $base_dir/dmidecode | wc -l"
	log "---"
	log

  else

    log "Pulp, a component of Katello, is a software repository management tool written in Python. Pulp provides complete software repository management and the capability to mirror repositories, the capability to host repositories, and the capability to distribute the contents of those repositories to a large number of consumers."
    log

    log "Pulp manages RPM content, Puppet modules, and container images in Satellite. Pulp also publishes Content Views and creates local repositories from which Capsules and hosts retrieve content. The configuration of the Apache HTTP Server determines how efficiently Pulp REST API requests are handled."
    log

    log "Pulp depends upon celery, which is responsible for launching Pulp workers, which download data from upstream repositories. Pulp also depends upon Apache HTTP Server to provide access to Pulp’s APIs and internal components."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for pulp services"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'pulp_celerybeat.service -|pulp_streamer.service -|pulp_workers.service -' | egrep -v '^\--' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// pulp_workers configuration"
	log "grep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY' $base_dir/etc/default/pulp_workers"
	log "---"
	log_cmd "grep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY' $base_dir/etc/default/pulp_workers"
	log "---"
	log

	log "// number of CPUs"
	log "grep processor $base_dir/proc/cpuinfo | wc -l"
	log "---"
	log_cmd "grep processor $base_dir/proc/cpuinfo | wc -l"
	log "---"
	log

	log "// number of sockets"
	log "grep 'Socket.Designation:' $base_dir/dmidecode | wc -l"
	log "---"
	log_cmd "grep 'Socket.Designation:' $base_dir/dmidecode | wc -l"
	log "---"
	log

	log "// Total number of pulp agents"
	log "grep pulp.agent $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671 | wc -l"
	log "---"
	log_cmd "grep pulp.agent $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671 | wc -l"
	log "---"
	log

	log "// Total number of (active) pulp agents"
	cmd="grep pulp.agent $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671 | grep \" 1.*1\$\""
	log "$cmd"
	log "---"
	if "$cmd" ]; then log_cmd "$cmd | wc -l"; fi
	log "---"
	log

	log "// number of tasks not finished"
	log "grep '\"task_id\"' $base_dir/sos_commands/pulp/pulp-running_tasks | wc -l"
	log "---"
	log_cmd "grep '\"task_id\"' $base_dir/sos_commands/pulp/pulp-running_tasks | wc -l"
	log "---"
	log


	log "// pulp task not finished"
	log "grep -E '(\"finish_time\" : null|\"start_time\"|\"state\"|\"pulp:|^})' $base_dir/sos_commands/pulp/pulp-running_tasks"
	log "---"
	log_cmd "grep -E '(\"finish_time\" : null|\"start_time\"|\"state\"|\"pulp:|^})' $base_dir/sos_commands/pulp/pulp-running_tasks"
	log "---"
	log

  fi


  log_tee "## Tomcat"
  log

  if [ ! "`egrep -i 'tomcat' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/tomcat" ] && [ ! -d "$base_dir/var/log/tomcat6" ]; then

	log "tomcat not found"
	log

  else

    #log "From Wikipedia:  Apache Tomcat is an open-source implementation of the Java Servlet, JavaServer Pages, Java Expression Language and WebSocket technologies. Tomcat provides a \"pure Java\" HTTP web server environment in which Java code can run."
    log "Apache Tomcat is a Java-based application development platform."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for tomcat.service"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'tomcat.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// Memory (Xms and Xmx)"
	log "grep tomcat $base_dir/ps"
	log "---"
	log_cmd "grep tomcat $base_dir/ps"
	log
	tomcat_mem=`grep tomcat $base_dir/ps | awk '{print $6}'`
	tomcat_mem_mb=`echo current memory consumption: $(($tomcat_mem / 1024 )) Mb 2>/dev/null`
	log "$tomcat_mem_mb"
	log_cmd "echo java heap memory maximum: `grep tomcat $base_dir/ps | tr ' ' '\n' | grep Xmx`"

	log
	log "grep 'JAVA_OPTS' $base_dir/etc/tomcat/tomcat.conf"
	log
	log_cmd "grep 'JAVA_OPTS' $base_dir/etc/tomcat/tomcat.conf"
	log "---"
	log

  fi


  log_tee "## Candlepin"
  log

  if [ ! "`egrep -i candlepin $base_dir/sos_commands/foreman/hammer_ping $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_foreman/var/log/candlepin" ]; then

	log "candlepin not found"
	log

  else

    log "Candlepin is a collection of tools that facilitates the management of software subscriptions, running on Tomcat. It is a part of Katello, which provides a unified workflow and web-based user interface for content and subscriptions. Candlepin provides the component of Katello related to subscriptions."
    log

	log "// hammer ping output"
	log "grep -A2 candlepin $base_dir/sos_commands/foreman/hammer_ping"
	log "---"
	log_cmd "grep -A2 candlepin $base_dir/sos_commands/foreman/hammer_ping"
	log "---"
	log

	log "// latest state of candlepin (updating info)"
	log "grep -B1 Updated $base_foreman/var/log/candlepin/candlepin.log"
	log "---"
	log_cmd "grep -B1 Updated $base_foreman/var/log/candlepin/candlepin.log | tail -100"
	log "---"
	log

	log "// ERROR on candlepin log - candlepin.log"
	log "{ for mylog in \`ls -rt $base_foreman/var/log/candlepin/candlepin.log*\`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c"
	log "---"
	if [ -f "$base_foreman/var/log/candlepin/candlepin.log" ];then
		{ for mylog in `ls -rt $base_foreman/var/log/candlepin/candlepin.log*`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c | tail -100 &>> $FOREMAN_REPORT
	else
		cmd="echo 'File candlepin.log not found.'"
	fi
	log "---"
	log

	log "// ERROR on candlepin log - error.log"
	log "{ for mylog in \`ls -rt $base_foreman/var/log/candlepin/error.log*\`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c"
	log "---"
	if [ -f "$base_foreman/var/log/candlepin/error.log" ];then
		{ for mylog in `ls -rt $base_foreman/var/log/candlepin/error.log*`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c | tail -100 &>> $FOREMAN_REPORT
	else
		cmd="echo 'File candlepin/error.log not found.'"
	fi
	log "---"
	log

	log "// latest entries on error.log"
	log "tail -30 $base_foreman/var/log/candlepin/error.log"
	log "---"
	log_cmd "tail -30 $base_foreman/var/log/candlepin/error.log"
	log "---"
	log

	log "// candlepin storage consumption"
	log "cat $base_dir/sos_commands/candlepin/du_-sh_.var.lib.candlepin"
	log "---"
	log_cmd "cat $base_dir/sos_commands/candlepin/du_-sh_.var.lib.candlepin"
	log "---"
	log

	log "Note:  In Satellite 6.4, activemq-artemis replaced hornetq.  Apache ActiveMQ Artemis is an open source project for an asynchronous messaging system."
	log

	log "// postgres idle processed (candlepin)"
	log "grep ^postgres $base_dir/ps | grep idle$ | grep \"candlepin candlepin\" | wc -l"
	log "---"
	log_cmd "grep ^postgres $base_dir/ps | grep idle$ | grep \"candlepin candlepin\" | wc -l"
	log "---"
	log

	log "// cpdb"
	log "cat $base_foreman/var/log/candlepin/cpdb.log"
	log "---"
	log_cmd "cat $base_foreman/var/log/candlepin/cpdb.log | tail -100"
	log "---"
	log

  fi



  log_tee "## virt-who"
  log

  if [ ! "`egrep -i 'virt-who|hypervisors' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/installed_rpms $base_dir/ps $base_dir/var/log/rhsm/rhsm.log $base_dir/sos_commands/foreman/foreman_tasks_tasks 2>/dev/null | head -1`" ] && [ ! -f "$base_dir/etc/sysconfig/virt-who" ] && [ ! -d "$base_dir/etc/virt-who.d" ]; then

	log "virt-who not found"
	log

  else

    log "The virt-who agent interrogates the hypervisor infrastructure and provides the host/guest mapping to the subscription service. It uses read-only commands to gather the host/guest associations for the subscription services. This way, the guest subscriptions offered by a subscription can be unlocked and available for the guests to use."
    log

	log "// service status"
	log "grep virt-who $base_dir/sos_commands/systemd/systemctl_list-units"
	log "---"
	log_cmd "egrep 'virt-who' $base_dir/sos_commands/systemd/systemctl_list-units | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// duplicated hypervisors #"
	log "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u | wc -l"
	log "---"
	log_cmd "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u | wc -l"
	log "---"
	log

	log "// duplicated hypervisors list"
	log "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u"
	log "---"
	log_cmd "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u"
	log "---"
	log

	log "// Sending updated Host-to-guest"
	log "grep \"Sending updated Host-to-guest\" $base_dir/var/log/rhsm/rhsm.log"
	log "---"
	log_cmd "grep \"Sending updated Host-to-guest\" $base_dir/var/log/rhsm/rhsm.log"
	log "---"
	log


	log "// virt-who default configuration"
	log "grep -v ^# $base_dir/etc/sysconfig/virt-who | grep -v ^$"
	log "---"
	log_cmd "grep -v ^# $base_dir/etc/sysconfig/virt-who | grep -v ^$"
	log "---"
	log

	log "// virt-who configuration"
	log "ls -l $base_dir/etc/virt-who.d"
	log "---"
	log_cmd "ls -l $base_dir/etc/virt-who.d"
	log "---"
	log

	log "// duplicated server entries on virt-who configuration"
	log "grep -h ^server $base_dir/etc/virt-who.d/*.conf | sort | uniq -c"
	log "---"
	log_cmd "grep -h ^server $base_dir/etc/virt-who.d/*.conf | sort | uniq -c"
	log "---"
	log

	log "// RHSM Warnings - virt-who"
	log "grep WARNING $base_dir/var/log/rhsm/rhsm.log"
	log "---"
	log_cmd "grep WARNING $base_dir/var/log/rhsm/rhsm.log | egrep 'virt-who' | tail -100"
	log "---"
	log

	  if [ "`file $base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF | head -1`" ]; then
	    log "// virt-who files with DOS line endings"
	    log "file $base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF"
	    log "---"
	    log_cmd "file $base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF"
	    log "---"
	    log
	  fi

	log "// Latest 30 hypervisors tasks"
	log "grep -E '(^                  id|Hypervisors)' $base_dir/sos_commands/foreman/foreman_tasks_tasks | sed -e 's/,/ /g' | sort -rk6 | head -n 30 | cut -d\| -f3,4,5,6,7"
	log "---"
	log_cmd "grep -E '(^                  id|Hypervisors)' $base_dir/sos_commands/foreman/foreman_tasks_tasks | sed -e 's/,/ /g' | sort -rk6 | head -n 30 | cut -d\| -f3,4,5,6,7 | egrep -i --color=always \"^|warning\""
	log "---"
	log

  fi




  log_tee "## qpidd"
  log

  if [ ! "`egrep -i 'qpidd' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps $base_dir/sos_commands/qpid/ls_-lanR_.var.lib.qpidd $base_dir/etc/qpid/qpidd.conf 2>/dev/null | head -1`" ]; then

	log "qpidd not found"
	log

  else

        log "Apache Qpid is a cross-platform Enterprise Messaging system that implements the Advanced Messaging Queue Protocol (AMQP)."
        log

        log "AMQP Messaging uses a Producer - Consumer model. Communication between the message producers and message consumers is decoupled by a broker that provides exchanges and queues. This allows applications to produce and consume data at different rates. Producers send messages to exchanges on the message broker. Consumers subscribe to exchanges that contain messages of interest, creating subscription queues that buffer messages for the consumer. Message producers can also create subscription queues and publish them for consuming applications."
        log

        log "The messaging broker functions as a decoupling layer, providing exchanges that distribute messages, the ability for consumers and producers to create public and private queues and subscribe them to exchanges, and buffering messages that are sent at-will by producer applications, and delivered on-demand to interested consumers."
        log

	log "// service status"
	log "grep foreman-maintain_service_status for qpidd.service"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'qpidd.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	if [ "`grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data 2>/dev/null | grep qpid`" ]; then
		log "// 3rd party qpidd packages"
		log "from file $base_dir/sos_commands/rpm/package-data"
		log "---"
		log_cmd "grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | grep qpid | grep -v ^$HOSTNAME | cut -f1,4 | sort -k2"
		log "---"
		log
	fi

	log "// qpidd disk usage"
	log "grep files from ls_-lanR_.var.lib.qpidd, add up the disk usage with awk and convert to Mb"
	log "---"
	QPIDD_DISK_USAGE=`grep "^-" $base_dir/sos_commands/qpid/ls_-lanR_.var.lib.qpidd 2>/dev/null | awk '{ s+=$5 } END {printf "%d", s}'`
	if [ "$QPIDD_DISK_USAGE" ]; then
		QPIDD_DISK_USAGE_MB=`echo $(($QPIDD_DISK_USAGE / 1024 )) Mb 2>/dev/null`
	else
	QPIDD_DISK_USAGE_MB=''
	fi
	log "$QPIDD_DISK_USAGE_MB"
	log "---"
	log


	log "// qpidd configuration"
	log "grep mgmt_pub_interval $base_dir/etc/qpid/qpidd.conf"
	log "---"
	log_cmd "grep mgmt_pub_interval $base_dir/etc/qpid/qpidd.conf"
	log "---"
	log

	log "// qpidd limits"
	log "grep LimitNOFILE $base_dir/etc/systemd/system/qpidd.service.d/90-limits.conf"
	log "---"
	log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/qpidd.service.d/90-limits.conf"
	log "---"
	log

  fi


  log_tee "## qdrouterd"
  log

  if [ ! "`egrep -i 'qdrouterd' $base_dir/sos_commands/systemd/systemctl_show_service_--all $base_dir/sos_commands/foreman/foreman-maintain_service_status $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

	log "qdrouterd not found"
	log

  else

    log "The qdrouterd service acts as an AMQP router.  Routers transfer messages between producers and consumers, but unlike message brokers, they do not take responsibility for messages.  The router network will deliver the message, possibly through several intermediate routers – and then route the consumer’s acknowledgement of that message back across the same path."
    log

    log "The qdrouterd service communicates with goferd, which is expected to run on the host servers (including capsule servers)."
    log

	log "// service status"
	log "grep foreman-maintain_service_status for qdrouterd"
	log "---"
	log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | tr '\r' '\n' | egrep \"^$|\.service -|Active:|All services\" | egrep -A2 'qdrouterd.service -' | egrep --color=always '^|failed|inactive|activating|deactivating'"
	log "---"
	log

	log "// qrouterd limits"
	log "grep LimitNOFILE $base_dir/etc/systemd/system/qdrouterd.service.d/90-limits.conf"
	log "---"
	log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/qdrouterd.service.d/90-limits.conf"
	log "---"
	log

  fi



  log_tee "## Subscription Watch"
  log

  if [ ! -f "$base_dir/etc/foreman-installer/scenarios.d/satellite.migrations/*-add-inventory-upload.rb" ] || [ ! "`egrep \"tfm-rubygem-foreman_rh_cloud|tfm-rubygem-foreman_inventory_upload\" $base_dir/installed-rpms`" ]; then

	log "subscription watch not found"
	log

  else

    log "Subscription watch provides unified reporting of Red Hat Enterprise Linux subscription usage information across the constituent parts of your hybrid infrastructure, including physical, virtual, on-premise, and cloud. This unified reporting model enhances your ability to consume, track, report, and reconcile your Red Hat subscriptions with your purchasing agreements and deployment types."
    log

    log "The use of Satellite as the data collection tool is useful for customers who have specific needs in their environment that either inhibit or prohibit the use of the Insights agent or the Subscription Manager agent for data collection."
    log

    log "// is the subscription watch foreman plugin installed?"
    log "---"
    log_cmd "egrep \"tfm-rubygem-foreman_rh_cloud|tfm-rubygem-foreman_inventory_upload\" $base_dir/installed-rpms"
    log_cmd "cat $base_dir/etc/foreman-installer/scenarios.d/satellite.migrations/*-add-inventory-upload.rb"
    log "---"
    log

    log "Note:  tfm-rubygem-foreman_rh_cloud is the current package for the Subscription Watch plugin.  tfm-rubygem-foreman_inventory_upload is the old one."
    log

  fi



## TODO

# cat apache/rpm_-V_httpd
# cat foreman/rpm_-V_foreman-debug
# cat krb5/rpm_-V_krb5-libs
# cat ldap/rpm_-V_openldap
# cat postgresql/rpm_-V_postgresql
# cat qpid/rpm_-V_qpid-cpp-server_qpid-tools
# cat qpid_dispatch/rpm_-V_qpid-dispatch-router
# cat tomcat/rpm_-V_tomcat
# cat virtwho/rpm_-V_virt-who

  echo
  echo "Calling xsos..."
  xsos -a $sos_path > xsos_results.txt
  log

#  if [ -f "/tmp/script/ins_check.sh" ]; then
	log_tee
        echo "Calling insights..."
	insights run -p shared_rules -F $sos_path >> $FOREMAN_REPORT
	log
	insights run -p telemetry -F $sos_path >> $FOREMAN_REPORT
        echo "done."
#  fi

  mv $FOREMAN_REPORT /tmp/report_${USER}_$final_name.log
  cp -f /tmp/report_${USER}_$final_name.log .
  chmod 666 ./report_${USER}_$final_name.log
  echo
  echo
  echo "## The output has been saved in these locations:"
  echo "    report_${USER}_$final_name.log"
  echo "    /tmp/report_${USER}_$final_name.log"
  echo ""

}


# Main

if [ "$1" == "" ]; then
  echo "Please supply the path of the sosreport that you would like to analyze."
  echo "$0 01234567/sosreport"
  exit 1
fi

main $1
