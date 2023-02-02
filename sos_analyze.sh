#!/bin/bash

exec 2>/dev/null


#
# Created ....: 03/04/2019
# Developer ..: Waldirio M Pinheiro <waldirio@gmail.com / waldirio@redhat.com>
# Purpose ....: Analyze sosreport and summarize the information (focus on Satellite info)
#

FOREMAN_REPORT="/tmp/$$.log"

# the following while block captures three flags from the command line
# -a enables ANSI color codes in the current directory, but not the copy in /tmp (has no effect unless -c or -l is also used)
# -c copies the output file from the /tmp directory to the current directory
# -l opens the output file from the current directory (implies -c by default)
# -t opens the output file from the /tmp directory
# -x generates a separate xsos report in the current directory, but not in /tmp

ANSI_COLOR_CODES=false
COPY_TO_CURRENT_DIR=false
OPEN_IN_VIM_RO_LOCAL_DIR=false
OPEN_IN_EDITOR_TMP_DIR=false
XSOS_REPORT=false

while getopts "acltx" opt "${NULL[@]}"; do
 case $opt in
    a )  # use ANSI color codes in the local file's output (but never the /tmp copy)
    ANSI_COLOR_CODES=true
    ;;
    c )
    COPY_TO_CURRENT_DIR=true
    ;;
   l )   # open copy from local directory.  Implies, and enables, option 'c' above.
   OPEN_IN_VIM_RO_LOCAL_DIR=true
   ;;
   t )   # open copy from /tmp/directory
   OPEN_IN_EDITOR_TMP_DIR=true
   ;;
   x )   # generate xsos report in current directory
   XSOS_REPORT=true
   ;;
    \? )
    ;;
 esac
done
shift "$(($OPTIND -1))"

MYPWD=`pwd`


main()
{
  > $FOREMAN_REPORT

  #sos_path=$1
  #base_dir=$sos_path
  #final_name=$(echo $base_dir | sed -e 's#/$##g' | grep -o sos.* | awk -F"/" '{print $NF}')

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

	    echo "This is not a sosreport directory.  Please provide the path to a correct sosreport directory."
	    exit 1

	  fi

	  sos_path=$base_dir
	  final_name=$(echo $base_dir | sed -e 's#/$##g' | grep -o sos.* | awk -F"/" '{print $NF}')

	  # configure the base_foreman variable based on the presence of foreman-debug directory

	  if [ -d $base_dir/sos_commands/foreman/foreman-debug ]; then
	    base_foreman="$base_dir/sos_commands/foreman/foreman-debug/"
	    #sos_version="old"
	    if [ ! -d "$base_foreman/var" ] && [ -d "$base_dir/var" ]; then
		ln -s -r "$base_dir/var" "$base_foreman/var"
	    fi
	    if [ ! -d "$base_foreman/etc" ] && [ -d "$base_dir/etc" ]; then
		ln -s -r "$base_dir/etc" "$base_foreman/etc"
	    fi
	  else
	    #sos_version="new"
	    #base_foreman=""
	    base_foreman=$base_dir
	  fi

	  NEWJOURNALFILE=`ls $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot_--since* 2>/dev/null | sort | tail -1`
	  if [ -d $base_dir/sos_commands/logs ] && [ ! -f $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot ] && [ "$NEWJOURNALFILE"  ]; then
		ln -s -r $NEWJOURNALFILE $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot
	  fi

	  echo "The sosreport is: $base_dir"												| tee -a $FOREMAN_REPORT

	  if [ ! -f "$base_dir/sysmgmt/links.txt" ]; then
	  	consolidate_differences
	  fi

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
	  echo -e "$1" | uniq | cut -b1-5120 >> $FOREMAN_REPORT
	}

	log_cmd()
	{
	  # echo "$@" | bash 2>&1 >> $FOREMAN_REPORT
	  echo "$@" | bash 2>/dev/null >> $FOREMAN_REPORT
	}

	# ref: https://unix.stackexchange.com/questions/44040/a-standard-tool-to-convert-a-byte-count-into-human-kib-mib-etc-like-du-ls1
	# Converts bytes value to human-readable string [$1: bytes value]
	#bytesToHumanReadable() {
	#    local i=${1:-0} d="" s=0 S=("Bytes" "KiB" "MiB" "GiB" "TiB" "PiB" "EiB" "YiB" "ZiB")
	#    while ((i > 1024 && s < ${#S[@]}-1)); do
	#        printf -v d ".%02d" $((i % 1024 * 100 / 1024))
	#        i=$((i / 1024))
	#        s=$((s + 1))
	#    done
	#    echo "$i$d ${S[$s]}"
	#}


	# The CSVLINKS variable contains files to which we want to link, along with alternate filenames found in older sosreport versions, foreman-debug files and satellite-debug files.

	CSVLINKS="sos_commands/block/blkid_-c_.dev.null,blkid
	sos_commands/boot/efibootmgr_-v,efibootmgr
	sos_commands/candlepin/du_-sh_.var.lib.candlepin,hornetq_disk_space
	sos_commands/cron/root_crontab,crontab_-l
	sos_commands/date/date,timestamp
	sos_commands/filesys/df_-ali_-x_autofs,df_-ali,df_-i
	sos_commands/filesys/df_-al_-x_autofs,df_-al,df_-h
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
	sos_commands/networking/ip_-d_address,ip_address,ip_a,ip_addr
	sos_commands/networking/ip_neigh_show_nud_noarp,ip_neigh_show
	sos_commands/networking/ip_route_show_table_all,ip_r
	sos_commands/networking/ip_-s_-d_link,ip_-s_link
	sos_commands/networking/iptables_-t_filter_-nvL,iptables_-t_mangle_-nvL
	sos_commands/networking/iptables_-vnxL,iptables_-t_nat_-nvL,iptables,firewall_tables
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
	sos_commands/filesys/mount_-l,mount
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
        sos_commands/mongodb/du_-sh_.var.lib.mongodb,/mongodb_disk_space
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
	sos_commands/katello/qpid-stat_-q_--ssl-certificate,qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671,qpid-stat_-q_--ssl-certificate_.etc.pki.pulp.qpid.client.crt_-b_amqps_..localhost_5671,qpid-stat-q
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
	sos_commands/memory/free,free_-h
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
	sos_commands/processor/lscpu,lscpu.out
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
	sos_commands/subscription_manager/subscription-manager_list_--all_--available,subscription-manager_available
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
	sos_commands/stratis/stratis_pool_list
	sos_commands/stratis/stratis_filesystem_list
	sos_commands/stratis/journalctl_--no-pager_--unit_stratisd
	sos_commands/systemtap/rpm_-qa_.bin.egrep_-e_kernel._uname_-r_-e_systemtap_-e_elfutils_
	sos_commands/x11/dmesg_grep_-e_agpgart
	etc/hosts
	etc/selinux/config,selinux_state
	etc/redhat-release
	var/log/httpd/foreman-ssl_access_ssl.log
	ifconfig,ifconfig_-a
	chkconfig,chkconfig_--list
	proc/cpuinfo
	date,date_--utc
	df,df_-al,df_-ali,df_-al_-x_autofs,df_-ali_-x_autofs,diskinfo,df_-h,df.out
	dmidecode
	hostname,hostname_-f
	installed-rpms,rpm-manifest,rpm-qa,rpm-qa.out,installed_packages
	ip_addr,ip_address,ip_a
	last
	lsb-release,lsb_release
	lsmod
	lsof,lsof_-b_M_-n_-l,lsof_-b_M_-n_-l_-c,lsof.out
	lspci,lspci_-nvv,lspci_-nnvv
	mount,mount_-l
	netstat,netstat_-W_-neopa,netstat_-neopa
	ps,ps_auxwww,ps_auxwwwm,ps_auxww,ps_auxww,ps_-elfL,ps_-elf,ps_axo_flags_state_uid_pid_ppid_pgid_sid_cls_pri_addr_sz_wchan_lstart_tty_time_cmd,ps_axo_pid_ppid_user_group_lwp_nlwp_start_time_comm_cgroup,ps-awfux,ps.out
	pstree
	route,route_-n
	uname,uname_-a
	uptime,uptime.out
	vgdisplay,vgdisplay_-vv_--config_global_locking_type_0
	database-character-sets,rhn-charsets
	database-schema-version,rhn-schema-version"

	SERVICE_LIST=$(egrep '\.service -' $base_dir/sos_commands/systemd/systemctl_status_--all -A 20 2>/dev/null | egrep -v "\`|\|" | sed s'/\●/\*/'g | egrep 'cockpit|goferd|elasticsearch|named|dhcpd|osbuild|postgres|httpd|puppet|redis|squid|foreman|tomcat|virt-who|qpidd|qdrouterd|mongod|celery|pulp|dynflow' -A 20)


	# The consolidate_differences function looks for files that are expected by our tools if they don't appear in the expected locations.  This can increase the utility of old sosreports and related files.

	consolidate_differences()
	{
	  echo
	  echo "creating soft links for compatibility..."
#	  echo

	  mkdir $base_dir/sysmgmt
	  echo 'created soft links for compatibility' > $base_dir/sysmgmt/links.txt

	  # create a few basic links

	  if [ ! -f "$base_dir/version.txt" ]; then touch $base_dir/version.txt; fi

	  if [ -d $base_dir/usr/lib ] && [ ! -e $base_dir/lib ]; then ln -sr $base_dir/usr/lib $base_dir/lib 2>/dev/null; fi

	  # this section handles spacewalk-debug files

	  if [ -d $base_dir/conf ]; then

		mkdir -p $base_dir/var/log
		ln -s conf $base_dir/etc 2>/dev/null

		if [ -d $base_dir/conf/tomcat/tomcat6 ]; then ln -sr $base_dir/conf/tomcat/tomcat6 $base_dir/conf/tomcat6 2>/dev/null; fi

		if [ -d $base_dir/httpd-logs/httpd ]; then ln -sr $base_dir/httpd-logs/httpd $base_dir/var/log/httpd 2>/dev/null; fi
		if [ -d $base_dir/tomcat-logs/tomcat6 ] && [ ! -e $base_dir/var/log/tomcat6 ]; then ln -sr $base_dir/tomcat-logs/tomcat6 $base_dir/var/log/tomcat6 2>/dev/null; fi
		if [ -d $base_dir/rhn-logs/rhn ]; then ln -sr $base_dir/rhn-logs/rhn $base_dir/var/log/rhn 2>/dev/null; fi
		if [ -d $base_dir/cobbler-logs ]; then ln -sr $base_dir/cobbler-logs $base_dir/var/log/cobbler 2>/dev/null; fi
		if [ -d $base_dir/audit-log ]; then ln -sr $base_dir/audit-log i$base_dir/var/log/audit 2>/dev/null; fi
		if [ -d $base_dir/schema-upgrade-logs ]; then ln -sr $base_dir/schema-upgrade-logs $base_dir/var/log/spacewalk/schema-upgrade 2>/dev/null; fi

		if [ -d $base_dir/containers ]; then
			mkdir -p $base_dir/sos_commands/podman
			if [ -f $base_dir/containers/ps ]; then ln -sr $base_dir/containers/ps $base_dir/sos_commands/podman/podman_ps 2>/dev/null; fi
		fi

	  fi


	  # this section links directories together to ensure that scripts can find their contents

	  if [ -d $base_dir/sos_commands/dmraid ] && [ ! -d $base_dir/sos_commands/devicemapper ]; then ln -s dmraid $base_dir/sos_commands/devicemapper 2>/dev/null; fi
	  if [ -d $base_dir/sos_commands/lsbrelease ]; then ln -s lsbrelease $base_dir/sos_commands/release 2>/dev/null; fi
	  if [ -d $base_dir/sos_commands/printing ]; then ln -s printing $base_dir/sos_commands/cups 2>/dev/null; fi
	  if [ -d $base_dir/sos_commands/sar ] && [ ! -e $base_dir/var/log/sar ]; then ln -sr $base_dir/sos_commands/sar $base_dir/var/log/sar; fi

	  # fix the hostname file for foreman-debug packages

	  if [ -f $base_dir/hostname_dns_check ] && [ ! -f $base_dir/hostname ]; then tail -1 $base_dir/hostname_dns_check | awk '{print $1}' > $base_dir/hostname; fi


	  # this section populates the sos_commands directory and various links in the root directory of the sosreport
	  # linking files we see within the sosreport

	   FINDRESULTS=`find $base_dir -type f \( -path $base_dir/run -prune -o -path $base_dir/sy -prune -o -path $base_dir/sos_strings -prune -o -path $base_dir/sos_reports -prune -o -path $base_dir/sos_logs -prune -o -path $base_dir/container -prune -o -path "$base_dir/proc/[0-9]*" -prune -o -path "$base_dir/proc/sys" -prune -o -path "$base_dir/proc/bus" -prune -o -path "$base_dir/proc/fs" -prune -o -path "$base_dir/proc/irq" -prune -o -path $base_dir/dev -prune -o -path $base_dir/sysmgmt -prune -o -path $base_dir/sys -prune \)  -o -print 2>/dev/null | sort -u | egrep -v "$base_dir\/container\/"`

#	   echo -e "$FINDRESULTS" | wc -l
#	   echo -e "$CSVLINKS" | wc -l


           # if any directories are found in "sos_commands/foreman/foreman-debug", then add soft links in "etc" to them
           if [ -d $base_dir/sos_commands/foreman/foreman-debug/etc ]; then

                mkdir -p $base_dir/etc 2>/dev/null
                FOREMAN_DIRS=`find $base_dir/sos_commands/foreman/foreman-debug/* -maxdepth 1 -type d | sed "s|$base_dir||g" | sed "s|sos_commands/foreman/foreman-debug/||g" | egrep '\/'`
				for i in `echo -e "$FOREMAN_DIRS" | awk -F"/" '{print $1}' | sort -u | tr '\n' ' ' | grep .`; do
						mkdir $base_dir/$i
				done
                for i in `echo -e "$FOREMAN_DIRS"`; do
                        if [ ! -e $base_dir/$i ]; then
                                ln -sr $i $base_dir/sos_commands/foreman/foreman-debug/$i $base_dir/$i
                        fi
                done

           fi


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

		FIRSTENTRY="${MYARRAY[0]}"
		FIRSTFILE=`basename "${MYARRAY[0]}"`
		MYDIR=`dirname "${MYARRAY[0]}"`

		if [ ! -f "$base_dir/$FIRSTENTRY" ]; then
		for i in "${MYARRAY[@]}"; do
			#let count=$count+1

			MYFILE=`basename $i`

			MATCH=`echo -e "$FINDRESULTS" | egrep "\/$MYFILE$"`

			if [ -f "$MATCH" ] && [ ! -L "$MATCH" ]; then
				mkdir -p "$base_dir/$MYDIR"
				ln -s -r "$MATCH" "$base_dir/$MYDIR/$FIRSTFILE" 2>/dev/null
				break
			fi
		done
		fi

	  done

	  # this section extracts the latest two versions of several frequently-queried log files
	  echo 'decompressing and caching frequently used logs...'

	  for i in `ls -rt $base_dir/var/log/messages* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done
	  for i in `ls -rt $base_foreman/var/log/foreman/production* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done
	  for i in `ls -rt $base_foreman/var/log/foreman-installer/satellite* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done
	  for i in `ls -rt $base_foreman/var/log/foreman-installer/capsule* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done
	  for i in `ls -rt $base_foreman/var/log/katello-installer/katello-installer* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done
	  for i in `ls -rt $base_foreman/var/log/foreman-maintain/foreman-maintain* | tail -4 | egrep gz$`; do gunzip $i 2>/dev/null; done


	  if [ "`ls -rt $base_dir/var/log/messages*`" ]; then
	  	cat `ls -rt $base_dir/var/log/messages* | tail -4` | egrep -v "\{|\}" | tail -10000 > $base_dir/sysmgmt/messages
	  	cat `ls -rt $base_dir/var/log/messages* | tail -4` | egrep "\{|\}" | egrep -v 'pulp_database.units_rpm|pulp_database.consumer_unit_profiles|pulp_database.units_package_group|pulp_database.units_erratum' | tail -1000 > $base_dir/sysmgmt/messages.mongo
	  fi

          if [ "`ls -rt $base_foreman/var/log/foreman/production*`" ]; then cat `ls -rt $base_foreman/var/log/foreman/production* | tail -4` | tail -10000 > $base_dir/sysmgmt/production.log; else touch $base_dir/sysmgmt/production.log; fi
          if [ "`ls -rt $base_foreman/var/log/foreman-installer/satellite*`" ]; then cat `ls -rt $base_foreman/var/log/foreman-installer/satellite* | tail -4` | tail -10000 > $base_dir/sysmgmt/satellite.log; else touch $base_dir/sysmgmt/satellite.log; fi
          if [ "`ls -rt $base_foreman/var/log/foreman-installer/capsule*`" ]; then cat `ls -rt $base_foreman/var/log/foreman-installer/capsule* | tail -4` | tail -10000 > $base_dir/sysmgmt/capsule.log; else touch $base_dir/sysmgmt/capsule.log; fi
          if [ "`ls -rt $base_foreman/var/log/katello-installer/katello-installer*`" ]; then cat `ls -rt $base_foreman/var/log/katello-installer/katello-installer* | tail -4` | tail -10000 > $base_dir/sysmgmt/katello-installer.log; else touch $base_dir/sysmgmt/katello-installer.log; fi
          if [ "`ls -rt $base_foreman/var/log/foreman-maintain/foreman-maintain*`" ]; then cat `ls -rt $base_foreman/var/log/foreman-maintain/foreman-maintain* | tail -4` | tail -10000 > $base_dir/sysmgmt/foreman-maintain.log; else touch $base_dir/sysmgmt/foreman-maintain.log; fi

	  if [ -f "$base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot" ] || [ -d "$base_dir/var/log/journal" ]; then
		cat `journalctl -D $base_dir/var/log/journal 2>/dev/null | tail -10000` $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot | egrep "^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" | sort -h | uniq | tail -10000 > $base_dir/sysmgmt/journal.log
	  else
		touch $base_dir/sysmgmt/journal.log
	  fi

	  #if [ -f "$base_dir/sos_commands/foreman/foreman-maintain_service_status" ]; then
	#	cp "$base_dir/sos_commands/foreman/foreman-maintain_service_status" "$base_dir/sysmgmt/services.txt"
	#	egrep '^\* puppet|^\* elasticsearch|^\* virt-who|^\* ntpd|^\* chronyd|^\* systemd-timedatectl|^\* cockpit|^\* named|^\* dhcpd|^\* osbuild' "$base_dir/sos_commands/systemd/systemctl_status_--all" -A 20 2>/dev/null >> "$base_dir/sysmgmt/services.txt"
	 # else
		touch "$base_dir/sysmgmt/services.txt"
		#egrep '\.service -' $base_dir/sos_commands/systemd/systemctl_status_--all -A 30 | egrep 'ntpd|chronyd|systemd-timedatectl|cockpit|goferd|elasticsearch|named|dhcpd|osbuild|postgres|httpd|puppet|redis|squid|foreman|tomcat|virt-who|qpidd|qdrouterd|mongod|celery|pulp|dynflow' -A 30 | sed s'/\●/\*/'g > "$base_dir/sysmgmt/services.txt"
		#cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed -n '/auditd.service -/,/Root Slice/p' | egrep '\.service -' -A 30 | egrep 'ntpd|chronyd|systemd-timedatectl|cockpit|goferd|elasticsearch|named|dhcpd|osbuild|postgres|httpd|puppet|redis|squid|foreman|tomcat|virt-who|qpidd|qdrouterd|mongod|celery|pulp|dynflow' -A 30 | sed s'/\●/\*/'g > $base_dir/sysmgmt/services.txt
		cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed -n '/service -/,/timer -/p' | sed -n '/service -/,/target -/p' | sed -n '/service -/,/swap -/p' | sed -n '/service -/,/socket -/p' | sed -n '/service -/,/slice -/p' | sed s'/\●/\*/'g | egrep '^\* ntpd|^\* chronyd|^\* systemd-timedatectl|^\* cockpit|^\* goferd|^\* elasticsearch|^\* named|^\* dhcpd|^\* osbuild|^\* postgres|^\* httpd|^\* light|^\* puppet|^\* redis|^\* squid|^\* foreman|^\* tomcat|^\* virt-who|^\* qpidd|^\* qdrouterd|^\* mongod|^\* rh-mongodb34-mongod|^\* celery|^\* pulp|^\* dynflow|^\* smart_proxy_dynflow_core' -A 20 | egrep -v 'displaying |\|-' &> $base_dir/sysmgmt/services.txt
	  #fi

	  tail -10000 $base_dir/var/log/httpd/foreman-ssl_access_ssl.log 2>/dev/null > $base_dir/sysmgmt/foreman-ssl_access_ssl.log

	  echo
	}

	# this is a list of red hat packages installed from the satellite repositories.
	# we'll use it later to highlight conflicting third-party packages.

	SATPACKAGES="dynflow|foreman|gofer|katello|mongo|passenger|pulp|qpid|satellite|^ansible-2|^ansiblerole-insights-client|^ansible-runner|^candlepin-|^candlepin-selinux|^createrepo_c-|^createrepo_c-libs-|^facter-|^hfsplus-tools-|^hiera-|^kobo-|^libmodulemd-|^libsolv-|^libstemmer-|^libwebsockets-|^liquibase-|^mod_xsendfile-|^ostree-|^pcp-mmvstatsd\-|^puppet|^pycairo-|^spacecmd-|^tracer-common-|^v8|^virt-who-|^yaml-cpp|^python2-amqp-|^python2-ansible-runner-|^python2-anyjson-|^python2-beautifulsoup4-|^python2-celery-|^python2-click-|^python2-crane-|^python2-daemon-|^python2-django-|^python2-future-|^python2-gobject-|^python2-gobject-base-|^python2-isodate-|^python2-itsdangerous-|^python2-jinja2-|^python2-jmespath-|^python2-markupsafe-|^python2-nectar-|^python2-okaara-|^python2-pexpect-|^python2-ptyprocess-|^python2-solv-|^python2-tracer-|^python2-twisted-|^python2-vine-|^python2-werkzeug-|^python-amqp-|^python-anyjson-|^python-argcomplete-|^python-billiard-|^python-blinker-|^python-bson-|^python-celery-|^python-crane-|^python-django-|^python-django-bash-completion-|^python-ecdsa-|^python-flask-|^python-fpconst-|^python-gnupg-|^python-httplib2-|^python-isodate-|^python-itsdangerous-|^python-kid-|^python-kombu-|^python-nectar-|^python-oauth2-|^python-okaara-|^python-passlib-|^python-psutil-|^python-requests-toolbelt-|^python-saslwrapper-|^python-semantic_version-|^python-simplejson-|^python-twisted-core-|^python-twisted-web-|^python-werkzeug-|^python-zope-interface-|^redhat-access-insights-puppet-|^repoview-|^rhel8-kickstart-setup-|^ruby-augeas-|^rubygem-ansi-|^rubygem-apipie-bindings-|^rubygem-awesome_print-|^rubygem-bundler_ext-|^rubygem-clamp-|^rubygem-concurrent-ruby-|^rubygem-facter-|^rubygem-faraday-|^rubygem-faraday_middleware-|^rubygem-fast_gettext-|^rubygem-ffi-|^rubygem-gssapi-|^rubygem-hashie-|^rubygem-highline-|^rubygem-infoblox-|^rubygem-journald-logger-|^rubygem-journald-native-|^rubygem-jwt-|^rubygem-kafo-|^rubygem-kafo_parsers-|^rubygem-kafo_wizards-|^rubygem-little-plugger-|^rubygem-logging-|^rubygem-logging-journald-|^rubygem-mime-types-|^rubygem-multi_json-|^rubygem-multipart-post-|^rubygem-netrc-|^rubygem-net-ssh-|^rubygem-newt-|^rubygem-oauth-|^rubygem-openscap-|^rubygem-powerbar-|^rubygem-rack-|^rubygem-rack-protection-|^rubygem-rake-|^rubygem-rb-inotify-|^rubygem-rest-client-|^rubygem-rkerberos-|^rubygem-rsec-|^rubygem-rubyipmi-|^rubygem-sinatra-|^rubygem-smart_proxy_ansible-|^rubygem-smart_proxy_discovery-|^rubygem-smart_proxy_openscap-|^rubygem-tilt-|^ruby-rgen-|^ruby-shadow-|^saslwrapper-|^SOAPpy-|^sshpass-|^tfm-ror52-rubygem-actioncable-|^tfm-ror52-rubygem-actionmailer-|^tfm-ror52-rubygem-actionpack-|^tfm-ror52-rubygem-actionview-|^tfm-ror52-rubygem-activejob-|^tfm-ror52-rubygem-activemodel-|^tfm-ror52-rubygem-activerecord-|^tfm-ror52-rubygem-activestorage-|^tfm-ror52-rubygem-activesupport-|^tfm-ror52-rubygem-arel-|^tfm-ror52-rubygem-builder-|^tfm-ror52-rubygem-coffee-rails-|^tfm-ror52-rubygem-coffee-script-|^tfm-ror52-rubygem-crass-|^tfm-ror52-rubygem-erubi-|^tfm-ror52-rubygem-execjs-|^tfm-ror52-rubygem-globalid-|^tfm-ror52-rubygem-i18n-|^tfm-ror52-rubygem-loofah-|^tfm-ror52-rubygem-mail-|^tfm-ror52-rubygem-marcel-|^tfm-ror52-rubygem-method_source-|^tfm-ror52-rubygem-mimemagic-|^tfm-ror52-rubygem-mime-types-|^tfm-ror52-rubygem-mini_mime-|^tfm-ror52-rubygem-mini_portile2-|^tfm-ror52-rubygem-multi_json-|^tfm-ror52-rubygem-mustermann-|^tfm-ror52-rubygem-nio4r-|^tfm-ror52-rubygem-nokogiri-|^tfm-ror52-rubygem-rack-|^tfm-ror52-rubygem-rack-test-|^tfm-ror52-rubygem-rails-|^tfm-ror52-rubygem-railties-|^tfm-ror52-rubygem-sinatra-|^tfm-ror52-rubygem-sprockets-|^tfm-ror52-rubygem-sqlite3-|^tfm-ror52-rubygem-thor-|^tfm-ror52-rubygem-thread_safe-|^tfm-ror52-rubygem-tilt-|^tfm-ror52-rubygem-turbolinks-|^tfm-ror52-rubygem-tzinfo-|^tfm-ror52-runtime-|^tfm-rubygem-activerecord-import-|^tfm-rubygem-addressable-|^tfm-rubygem-algebrick-|^tfm-rubygem-ancestry-|^tfm-rubygem-anemone-|^tfm-rubygem-ansi-|^tfm-rubygem-apipie-bindings-|^tfm-rubygem-apipie-params-|^tfm-rubygem-apipie-rails-|^tfm-rubygem-audited-|^tfm-rubygem-autoparse-|^tfm-rubygem-awesome_print-|^tfm-rubygem-bastion-|^tfm-rubygem-bcrypt-|^tfm-rubygem-bundler_ext-|^tfm-rubygem-clamp-|^tfm-rubygem-colorize-|^tfm-rubygem-concurrent-ruby-|^tfm-rubygem-css_parser-|^tfm-rubygem-daemons-|^tfm-rubygem-deacon-|^tfm-rubygem-declarative-|^tfm-rubygem-declarative-option-|^tfm-rubygem-deep_cloneable-|^tfm-rubygem-deface-|^tfm-rubygem-diffy-|^tfm-rubygem-docker-api-|^tfm-rubygem-domain_name-|^tfm-rubygem-ethon-|^tfm-rubygem-excon-|^tfm-rubygem-extlib-|^tfm-rubygem-facter-|^tfm-rubygem-faraday-|^tfm-rubygem-fast_gettext-|^tfm-rubygem-ffi-|^tfm-rubygem-fog-|^tfm-rubygem-fog-aws-|^tfm-rubygem-fog-core-|^tfm-rubygem-fog-digitalocean-|^tfm-rubygem-fog-google-|^tfm-rubygem-fog-json-|^tfm-rubygem-fog-kubevirt-|^tfm-rubygem-fog-libvirt-|^tfm-rubygem-fog-openstack-|^tfm-rubygem-fog-ovirt-|^tfm-rubygem-fog-rackspace-|^tfm-rubygem-fog-vsphere-|^tfm-rubygem-fog-xenserver-|^tfm-rubygem-fog-xml-|^tfm-rubygem-foreigner-|^tfm-rubygem-formatador-|^tfm-rubygem-friendly_id-|^tfm-rubygem-get_process_mem-|^tfm-rubygem-gettext-|^tfm-rubygem-gettext_i18n_rails-|^tfm-rubygem-git-|^tfm-rubygem-google-api-client-|^tfm-rubygem-googleauth-|^tfm-rubygem-graphql-|^tfm-rubygem-graphql-batch-|^tfm-rubygem-gssapi-|^tfm-rubygem-hammer_cli-|^tfm-rubygem-hammer_cli_csv-|^tfm-rubygem-hammer_cli_import-|^tfm-rubygem-hashie-|^tfm-rubygem-highline-|^tfm-rubygem-http-|^tfm-rubygem-httpclient-|^tfm-rubygem-http-cookie-|^tfm-rubygem-http-form_data-|^tfm-rubygem-http_parser-|^tfm-rubygem-i18n-|^tfm-rubygem-ipaddress-|^tfm-rubygem-jgrep-|^tfm-rubygem-journald-logger-|^tfm-rubygem-journald-native-|^tfm-rubygem-jquery-ui-rails-|^tfm-rubygem-jwt-|^tfm-rubygem-katello-|^tfm-rubygem-kubeclient-|^tfm-rubygem-launchy-|^tfm-rubygem-ldap_fluff-|^tfm-rubygem-little-plugger-|^tfm-rubygem-locale-|^tfm-rubygem-logging-|^tfm-rubygem-logging-journald-|^tfm-rubygem-memoist-|^tfm-rubygem-ms_rest-|^tfm-rubygem-multi_json-|^tfm-rubygem-multipart-post-|^tfm-rubygem-net-ldap-|^tfm-rubygem-net-ping-|^tfm-rubygem-netrc-|^tfm-rubygem-net-scp-|^tfm-rubygem-net-ssh-|^tfm-rubygem-net-ssh-krb-|^tfm-rubygem-nokogiri-|^tfm-rubygem-oauth-|^tfm-rubygem-optimist-|^tfm-rubygem-os-|^tfm-rubygem-ovirt-engine-sdk-|^tfm-rubygem-parse-cron-|^tfm-rubygem-pg-|^tfm-rubygem-polyglot-|^tfm-rubygem-powerbar-|^tfm-rubygem-prometheus-client-|^tfm-rubygem-promise-|^tfm-rubygem-public_suffix-|^tfm-rubygem-quantile-|^tfm-rubygem-rabl-|^tfm-rubygem-rack-cors-|^tfm-rubygem-rack-jsonp-|^tfm-rubygem-rails-i18n-|^tfm-rubygem-rails-observers-|^tfm-rubygem-rainbow-|^tfm-rubygem-rbovirt-|^tfm-rubygem-rbvmomi-|^tfm-rubygem-record_tag_helper-|^tfm-rubygem-redhat_access-|^tfm-rubygem-redhat_access_lib-|^tfm-rubygem-representable-|^tfm-rubygem-responders-|^tfm-rubygem-rest-client-|^tfm-rubygem-retriable-|^tfm-rubygem-roadie-|^tfm-rubygem-roadie-rails-|^tfm-rubygem-robotex-|^tfm-rubygem-ruby2ruby-|^tfm-rubygem-ruby-libvirt-|^tfm-rubygem-ruby_parser-|^tfm-rubygem-runcible-|^tfm-rubygem-safemode-|^tfm-rubygem-scoped_search-|^tfm-rubygem-secure_headers-|^tfm-rubygem-sequel-|^tfm-rubygem-sexp_processor-|^tfm-rubygem-signet-|^tfm-rubygem-sprockets-|^tfm-rubygem-sprockets-rails-|^tfm-rubygem-sshkey-|^tfm-rubygem-statsd-instrument-|^tfm-rubygem-table_print-|^tfm-rubygem-text-|^tfm-rubygem-timeliness-|^tfm-rubygem-trollop-|^tfm-rubygem-turbolinks-|^tfm-rubygem-typhoeus-|^tfm-rubygem-uber-|^tfm-rubygem-unf-|^tfm-rubygem-unf_ext-|^tfm-rubygem-unicode-|^tfm-rubygem-useragent-|^tfm-rubygem-webpack-rails-|^tfm-rubygem-wicked-|^tfm-rubygem-will_paginate-|^tfm-rubygem-x-editable-rails-|^tfm-rubygem-zest-|^tfm-runtime-"


	report()
	{


	  # define variables to be used later
	  CAPSULE_IPS=""
	  base_dir=$1
	  base_foreman=$2
	  sos_version=$3

	  HOSTNAME=""
	  if [ -f "$base_dir/hostname" ]; then HOSTNAME=`cat $base_dir/hostname`; fi
	  CAPSULE_IPS=""
	  HOSTS_ENTRY=""
	  if [ -f "$base_dir/etc/hosts" ] && [ "$HOSTNAME" ]; then HOSTS_ENTRY=`grep $HOSTNAME $base_dir/etc/hosts | egrep --color=always '^|$IPADDRLIST'`; fi

	  PRIMARYNIC=""
	  if [ -f "$base_dir/route" ]; then PRIMARYNIC=`grep UG $base_dir/route | awk '{print $NF}'`; fi

	  IPADDRLIST=""
	  SATELLITE_IP=""
	  if [ -f "$base_dir/ip_addr" ]; then SATELLITE_IP=`egrep "$PRIMARYNIC" $base_dir/ip_addr | egrep -v "inet6" | awk '{print $4}' | awk -F"/" '{print $1}' | tr '\n' '|' | rev | cut -c2- | rev`; fi
	  IPADDRLIST=$SATELLITE_IP


	  log_tee "### Welcome to Report ###"
	  log_tee "### CEE/SysMGMT ###"
	  log_tee " "



	  log_tee "## Date"
	  log

	  log "// date sosreport was collected"
	  log "---"
	  log_cmd "head -1 $base_dir/date"
	  log "---"
	  log

          log_tee "## Case Summary"
          log

          log "// environment for case summary"
          log "---"
          log "ENVIRONMENT:"
          log
          if [ -f "$base_dir/installed-rpms" ]; then
                log_cmd "egrep '^satellite-6|^satellite-capsule-6|^spacewalk|rhui|rhua|clientrpmtest' $base_dir/installed-rpms | awk '{print \$1}' | egrep -v 'tfm-rubygem'"
          else
                log_cmd "cat $base_dir/etc/redhat-release"
          fi
          log_cmd "grep release $base_dir/installed-rpms 2>&1 | awk '{print \$1}' | egrep -i 'redhat|oracle|centos|suse|fedora' | egrep -v 'eula|base'"
          if [ "`grep :scenario: $base_dir/etc/foreman-installer/scenarios.d/last_scenario.yaml 2>/dev/null | sed s'/:scenario://'g  | awk -F\":\" '{print $2}'`" ]; then
                log_cmd "grep :scenario: $base_dir/etc/foreman-installer/scenarios.d/last_scenario.yaml"
          fi
          log
          log "HW platform:"
          log
          log_cmd "{ grep -E '(Vendor|Manufacture|Product Name:|Description:)' $base_dir/dmidecode | head -n3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; } || { grep virtual $base_dir/facts 2>/dev/null | egrep \"vendor|version|manufacturer|name\" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; }"
          log "---"
          log

	  log_tee "## hostname"
	  log

	  log "---"
	  log "from \$base_dir/etc/hostname:"
	  log_cmd "cat $base_dir/hostname | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
          log
          log "from \$base_dir/sos_commands/host/hostnamectl_status"
          log_cmd "egrep hostname $base_dir/sos_commands/host/hostnamectl_status | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
	  log
	  log "from \$base_dir/var/lib/rhsm/facts/facts.json:"
	  log_cmd "jq '. | \"hostname: \" + .\"network.hostname\",\"FQDN: \" + .\"network.fqdn\"' $base_dir/var/lib/rhsm/facts/facts.json 2>/dev/null | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
          log
          log "from \$base_dir/etc/sysconfig/network (useful for RHEL 6):"
          log_cmd "cat $base_dir/etc/sysconfig/network | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME|HOSTNAME'"

	  if [ -f "$base_dir/etc/foreman-proxy/ssl_cert.pem" ]; then
	    log
	    log "foreman certificates:"
	    log "openssl x509 -in \$base_dir/etc/foreman-proxy/ssl_cert.pem -noout -text | egrep 'CN=|DNS|Issuer'"
	    log
	    log_cmd "openssl x509 -in $base_dir/etc/foreman-proxy/ssl_cert.pem -noout -text | sed 's/$/\$/' | egrep 'CN=|DNS|Issuer|Subject Alternative Name' | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
	    log
	    #log "openssl x509 -in \$base_dir/etc/foreman-proxy/foreman_ssl_ca.pem -noout -text | egrep -i 'before|after'"
	    #log
	    #log_cmd "openssl x509 -in $base_dir/etc/foreman-proxy/foreman_ssl_ca.pem -noout -text | egrep -i 'before|after'"

	    log "check certificates in \$base_dir/etc/foreman-proxy/ for beginning and ending dates"
	    log

	    #OUTPUT=$(MYDATE=`date -d "\`cat $base_dir/date\`" +"%Y%m%d%H%M"`;
	    OUTPUT=$(MYDATE=`date +"%Y%m%d%H%M"`;
		for i in `find $base_dir/etc/foreman-proxy -type f -exec file {} \; | egrep -v key | egrep 'certificate|\.pem|\.crt' | awk -F":" '{print $1}' | sort`; do 
			echo $i; 
			START_DATE=`openssl x509 -in $i -noout -text | egrep -i "not before" | sed s'/Not Before://'g | sed 's/^[ \t]*//;s/[ \t]*$//'`; 
			END_DATE=`openssl x509 -in $i -noout -text | egrep -i "not after" | sed s'/Not After ://'g | sed 's/^[ \t]*//;s/[ \t]*$//'`; 
			if [ "`date -d \"$START_DATE\" +\"%Y%m%d%H%M\"`" -gt "$MYDATE" ]; then 
				echo -n 'Not Before: ';
				echo "$START_DATE" | egrep . --color='ALWAYS'; 
			else 
				echo -n 'Not Before: ';
				echo "$START_DATE"; 
			fi; 
			echo -n 'Not After : '; 
			if [ "`date -d \"$END_DATE\" +\"%Y%m%d%H%M\"`" -lt "$MYDATE" ]; then 
				echo -n 'Not Before: ';
				echo "$END_DATE" | egrep . --color='ALWAYS'; 
			else 
				echo -n 'Not Before: ';
				echo "$END_DATE"; 
			fi; 
			echo; 
		done;)

	    log_cmd "echo -e \"$OUTPUT\""
	    log
	    log
	  
	  fi

	  if [ "$HOSTS_ENTRY" ]; then
	    log
	    log "from \$base_dir/etc/hosts:"
	    log "---"
	    log_cmd "GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME|$IPADDRLIST' $base_dir/etc/hosts"
	    log "---"
	    log 
	  fi

	  
            log
            log "cat \$base_dir/etc/rhsm/facts/uuid.facts"
            log "---"
            log_cmd "cat $base_dir/etc/rhsm/facts/uuid.facts | GREP_COLORS='ms=01;33' egrep -i --color=always '^|$HOSTNAME'"
            log "---"
            log

          if [ -f "$base_dir/sos_commands/foreman/foreman_tasks_tasks" ]; then
                log "// Satellite's organization list"
                log "from file \$base_dir/sos_commands/foreman/foreman_tasks_tasks"
                log "---"
                SATORGS=`egrep organization $base_dir/sos_commands/foreman/foreman_tasks_tasks | awk -F"'" '{print $6}' | sort -u`
		log_cmd "echo -e \"$SATORGS\""
                log "---"
                log
          fi


	  CAPSULE_IPS=""
	  if [ -f "$base_dir/sos_commands/foreman/smart_proxies" ]; then
	  if [ "`grep satellite-6 $base_dir/installed-rpms 2>&1`" != '' ] || [ "`grep capsule $base_dir/installed-rpms 2>&1`" == '' ]; then
		log "// capsule servers"
		log "grep -v row \$base_dir/sos_commands/foreman/smart_proxies"
		log "---"
		log_cmd "grep -v row $base_dir/sos_commands/foreman/smart_proxies | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME|$IPADDRLIST'"
		log "---"
		log

		CAPSULE_IPS=`egrep https: $base_dir/sos_commands/foreman/smart_proxies | awk '{print $7}' | grep . | tr '\n' '|' | rev | cut -c2- | rev`
	  else
		CAPSULE_IPS=$IPADDRLIST
	  fi
	  else
		CAPSULE_IPS=$IPADDRLIST
	  fi

	  if [ -f "$base_dir/etc/sysconfig/networking/profiles/default/network" ]; then
                log "// hostname in RHEL5 network profiles file"
                log "grep -i ^hostname \$base_dir/etc/sysconfig/networking/profiles/default/network"
                log "---"
                log_cmd "grep -i ^hostname $base_dir/etc/sysconfig/networking/profiles/default/network | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
                log "---"
                log
	  fi

	  log
          log "// cloned hostname check"
          log "---"
          log "ls \$base_dir/etc/machine-id \$base_dir/etc/rhsm/facts/katello.facts"
          log
	  log_cmd "ls $base_dir/etc/machine-id $base_dir/etc/rhsm/facts/katello.facts"
	  log
	  if [ -f "$base_dir/etc/rhsm/facts/katello.facts" ]; then
	    log_cmd "jq '.' $base_dir/etc/rhsm/facts/katello.facts | GREP_COLORS='ms=01;33' egrep --color=always '^|$HOSTNAME'"
	  fi
          log "---"
          log


	  if [ -f "$base_dir/etc/foreman-proxy/ssl_cert.pem" ] && [ -f "$base_dir/etc/foreman/proxy_ca.pem" ]; then
	  log "// key match check"
	  log "---"
	  log "from \$base_dir/etc/foreman-proxy/ssl_cert.pem and \$base_dir/etc/foreman/proxy_ca.pem"
	  log
	  SSL_CERT=`openssl x509 -in $base_dir/etc/foreman-proxy/ssl_cert.pem -text -noout | grep -A 1 'Authority Key Identifier' | tail -1 | awk '{print $1}' | sed s'/keyid://'g`
	  PROXY_CA=`openssl x509 -in $base_dir/etc/foreman/proxy_ca.pem -text -noout | grep -A 1 'Subject Key Identifier' | tail -1 | awk '{print $1}'`
	  log "$SSL_CERT"
	  log "$PROXY_CA"
	  diff <(echo $SSL_CERT) <(echo $PROXY_CA);if [ "$?" -eq 0 ]; then log "certificates match"; else log "certificates differ"; fi
	  log "---"
	  log
	  fi

          if [ "`grep satellite-6 $base_dir/installed-rpms`" ]; then
          	log "// answers file certs"
		log "egrep -A 3 server_cert: \$base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml"
          	log "---"
	  	log_cmd "egrep -A 3 server_cert: $base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml"
          	log
          	log "---"
         	log

                log "// ssl-build directory lines"
                log "---"
                #log "wc -l \$base_dir/sos_commands/foreman/ls_-lanR_.root.ssl-build"
                #log_cmd "wc -l $base_dir/sos_commands/foreman/ls_-lanR_.root.ssl-build"
		log "egrep -hc . \$base_dir/sos_commands/foreman/ls_-lanR_.root.ssl-build"
		log_cmd "egrep -hc . $base_dir/sos_commands/foreman/ls_-lanR_.root.ssl-build"
                log
                log "---"
                log

	  elif [ "`grep ^satellite-capsule $base_dir/installed-rpms`" ]; then
		log "// answers file certs"
		log "egrep -A 3 server_cert: \$base_dir/etc/foreman-installer/scenarios.d/capsule-answers.yaml"
          	log "---"
          	log_cmd "egrep -A 3 server_cert: $base_dir/etc/foreman-installer/scenarios.d/capsule-answers.yaml"
          	log
          	log "---"
          	log
          fi


          log "// disconnected mode?"
          log "---"
          log_cmd "egrep disconnected $base_dir/sos_commands/foreman/foreman_settings_table | grep true | sed s'/  //'g"
          log "---"
          log



	  #log_tee "## Case Summary"
	  #log

	  #log "// environment for case summary"
	  #log "---"
	  #log "ENVIRONMENT:"
	  #log
	  #if [ -f "$base_dir/installed-rpms" ]; then
	#	log_cmd "egrep '^satellite-6|^satellite-capsule-6|^spacewalk|rhui|rhua|clientrpmtest' $base_dir/installed-rpms | awk '{print \$1}' | egrep -v 'tfm-rubygem'"
	 # else
	#	log_cmd "cat $base_dir/etc/redhat-release"
	 # fi
	  #log_cmd "grep release $base_dir/installed-rpms 2>&1 | awk '{print \$1}' | egrep -i 'redhat|oracle|centos|suse|fedora' | egrep -v 'eula|base'"
	  #if [ "`grep :scenario: $base_dir/etc/foreman-installer/scenarios.d/last_scenario.yaml 2>/dev/null | sed s'/:scenario://'g  | awk -F\":\" '{print $2}'`" ]; then
	#	log_cmd "grep :scenario: $base_dir/etc/foreman-installer/scenarios.d/last_scenario.yaml"
	  #fi

	  #log
	  #log "HW platform:"
	  #log
	  #log_cmd "{ grep -E '(Vendor|Manufacture|Product Name:|Description:)' $base_dir/dmidecode | head -n3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; } || { grep virtual $base_dir/facts 2>/dev/null | egrep \"vendor|version|manufacturer|name\" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u; }"
	  #log "---"
	  #log



	  log_tee "## Platform"
	  log

	  log "// operating system"
	  log "---"
	  log_cmd "cat $base_dir/etc/redhat-release 2>/dev/null || grep -A9 '^os =>' $base_dir/facts"
	  log "---"
	  log

          if [ -f "$base_dir/etc/os-release" ]; then
		log "// os-release file details"
                log_cmd "egrep '^NAME=|^VERSION=' $base_dir/etc/os-release"
		log
          fi

	  log "// release version (for version locking)"
	  log "jq '.' \$base_dir/var/lib/rhsm/cache/releasever.json"
	  log "cat \$base_dir/etc/yum/vars/releasever 2>/dev/null"
	  log "cat \$base_dir/sos_commands/sos_commands/subscription_manager/subscription-manager_release_--show 2>/dev/null"
	  log "---"
	  log_cmd "jq '.' $base_dir/var/lib/rhsm/cache/releasever.json 2>/dev/null"
          log "---"
	  log_cmd "cat $base_dir/etc/yum/vars/releasever 2>/dev/null; echo"
          log "---"
	  log_cmd "cat $base_dir/sos_commands/sos_commands/subscription_manager/subscription-manager_release_--show 2>/dev/null"
	  log "---"
	  log

	  log "// release packages"
	  log "grep release \$base_dir/installed-rpms | awk '{print \$1}'"
	  log "---"
	  RELEASE_PACKAGE=`grep release $base_dir/installed-rpms 2>&1 | awk '{print $1}' | egrep -v "eula|No such file or directory"`
	  log "$RELEASE_PACKAGE"
	  log "---"
	  log

	  log "// baremetal or vm?"
	  log "grep dmidecode and facts files for vendor and manufacturer"
	  log "---"
	  log_cmd "grep -E '(Vendor|Manufacture|Product Name:|Description:)' $base_dir/dmidecode 2>/dev/null | head -n3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u"
	  log_cmd "grep virtual $base_dir/facts 2>/dev/null | egrep \"vendor|version|manufacturer|name\" | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -u"
	  log
	  log_cmd "egrep 'Chassis:|Virtualization:|Hardware' $base_dir/sos_commands/host/hostnamectl_status"
	  log "---"
	  log

	  log_tee "## Memory"
	  log

	  log "// out of memory errors"
	  log "grep messages files for out of memory errors"
	  log "---"
	  #{ for mylog in `ls -rt $base_dir/var/log/messages* $base_dir/OOO 2>/dev/null`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep 'Out of memory' | egrep -v '{|}|HeapDumpOnOutOfMemoryError' | tail -200 | cut -c -10240 >> $FOREMAN_REPORT
	  #log_cmd "egrep -hir 'out of memory' $base_dir/var/log/messages $base_dir/sos_commands/logs/journalctl_--no-pager $base_dir/OOO | egrep -v '{|}|HeapDumpOnOutOfMemoryError' | tail -100"
	  #log_cmd "egrep -hir 'out of memory' $base_dir/var/log/messages $base_dir/sos_commands/logs/journalctl_--no-pager $base_dir/OOO 2>/dev/null | egrep -v '{|}|HeapDumpOnOutOfMemoryError' | sort -h | tail -100"

	  log_cmd "egrep -hir 'out of memory' $base_dir/sysmgmt/{messages,journal.log} | egrep -v '{|}|HeapDumpOnOutOfMemoryError' | sort -h | tail -100"
	  log "---"
	  log

	  log "// top 5 memory consumers by process"
	  log "cat \$base_dir/ps | sort -nrk6 | head -n5"
	  log "---"
	  log_cmd "cat $base_dir/ps 2>&1 | sort -nrk6 | head -n5"
	  log "---"
	  log

	  log "// top memory consumers by user"
	  log "from \$base_dir/ps"
	  log "---"
	  log "Total Memory Consumed in KiB: $memory_usage"
	  log "Total Memory Consumed in GiB: $memory_usage_gb"
	  log
	  log_cmd "cat $base_dir/ps 2>&1 | sort -nr | awk '{print \$1, \$6}' | grep -v ^USER | grep -v ^COMMAND | grep -v \"^ $\" | awk  '{a[\$1] += \$2} END{for (i in a) print i, a[i]}' | sort -nrk2"
	  log "---"
	  log

	  log "// memory usage"
	  log "cat $base_dir/free"
	  log "---"
	  log_cmd "cat $base_dir/free"
	  log " "
	  memory_usage=$(cat $base_dir/ps 2>&1 | sort -nr | awk '{print $6}' | grep -v ^RSS | grep -v ^$ | paste -s -d+ | bc)
	  memory_usage_gb=$(echo "scale=2;$memory_usage/1024/1024" | bc)
	  log "Total Memory Consumed in GiB: $memory_usage_gb"
	  log "---"
	  log

	  log "// xsos memory info"
	  log "xsos --mem \$base_dir"
	  log "---"
	  log_cmd "xsos --mem $base_dir 2>/dev/null"
	  log "---"
	  log

          log "// error: Setting puppetrun has no definition"
          log "---"
          log "count occurrences in sos_commands/logs/journalctl_--no-pager_--catalog_--boot*"
          log_cmd "egrep -hcir 'Setting puppetrun has no definition' $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot*"
          log "---"
          log

          log "// tuning profile"
          log "egrep -hir 'tuning' \$base_foreman/var/log/foreman-installer | egrep -vi 'choices|path|hook' | uniq -f 4 | sort -h"
          log "---"
          log_cmd "egrep -hir 'tuning' $base_foreman/var/log/foreman-installer | egrep -vi 'choices|path|hook|migration' | uniq -f 4 | sort -h"
          log "---"
          log

	  log "// custom hiera"
	  log "cat \$base_foreman/etc/foreman-installer/custom-hiera.yaml"
          log "---"
	  log_cmd "cat $base_foreman/etc/foreman-installer/custom-hiera.yaml 2>&1 | egrep -v '\#|---' | egrep --color=always '^|checkpoint_segments|apache::purge_configs: false'"
	  log "---"
	  log
	  log "Note: The checkpoint_segments parameter is incompatible with Satellite 6.8 and above."
	  log "Note: The qpid file limits were introduced in Satellite 6.4."
	  log "Note:  The setting \"apache::purge_configs: false\" is incompatible with Satellite 6.10 and above."
	  log

	  if [ "`egrep . $base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf $base_dir/etc/httpd/conf.d/passenger.conf 2>/dev/null | head -1`" ] || [ "`egrep -i general $base_dir/sos_commands/foreman/passenger-status_--show_pool 2>/dev/null | head -1`" ]; then

                log "// passenger.conf configuration - 6.3 or earlier"
                log "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' \$base_dir/etc/httpd/conf.d/passenger.conf"
                log "---"
                log_cmd "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.d/passenger.conf | grep -v \#"
                log "---"
                log

                log "// passenger pool status"
                log "egrep -A 3 'General information' \$base_dir/sos_commands/foreman/passenger-status_--show_pool"
                log "---"
                log_cmd "egrep -A 3 'General information' $base_dir/sos_commands/foreman/passenger-status_--show_pool"
                log "---"
                log

	  fi

          if [ -f "$base_dir/etc/sysconfig/dynflowd" ]; then

                log "// dynflow optimizations (only used before 6.8)"
                log "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" \$base_dir/etc/sysconfig/foreman-tasks"
                log "---"
                log_cmd "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/foreman-tasks"
                log
                log "---"
		log
		log "Note:  For Satellite servers older than 6.8, EXECUTORS_COUNT=2 is recommended for 32 Gb of RAM, and EXECUTORS_COUNT=3 is recommended for 65+ Gb of RAM."
                log

	  fi


          log "// number of CPUs"
          log "egrep -hc processor \$base_dir/proc/cpuinfo"
          log "---"
          log_cmd "if [ -f $base_dir/sos_commands/processor/lscpu ]; then egrep '^CPU\(s\):' $base_dir/sos_commands/processor/lscpu; elif [ -f $base_dir/proc/cpuinfo ]; then egrep -hc processor $base_dir/proc/cpuinfo; elif [ -f $base_dir/procs ]; then cat $base_dir/procs; fi"
          log "---"
          log


           log "// pulp_workers configuration"
           log "egrep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY|pulpcore_worker_count' \$base_dir/etc/default/pulp_workers \$base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}"
           log "---"
           log_cmd "egrep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY|pulpcore_worker_count' $base_dir/etc/default/pulp_workers $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}"
           log "---"
           log


	  log_tee "## Storage"
	  log

	  log "// no space left on device"
	  #log "'no space left on device' errors in \$base_dir"
	  log "---"
	  #log_cmd "egrep -hir 'no space left on device' $base_dir 2>/dev/null | egrep -v '{|}' | egrep \"`date +'%Y' --date='-2 months'`|`date +'%Y'`\" | sed s'/\\n/\n/'g | sed s'/\[Sun //'g | sed s'/\[Mon //'g | sed s'/\[Tue //'g | sed s'/\[Wed //'g | sed s'/\[Thu //'g | sed s'/\[Fri //'g | sed s'/\[Sat //'g | sort -h"
	  log "postgres logs:"
	  log_cmd "egrep -ir 'No space left on device$' $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log -h | sort -k1 -k2 | tail -10"
	  log

	  log "redis logs:"
	  log_cmd "egrep -hir 'No space left on device$' $base_dir/var/log/redis | sort -k4h -k3M -k2h -k5 | tail -10"
	  log

	  log "dmesg logs:"
	  log_cmd "egrep -hi 'no space left on device' $base_dir/sos_commands/kernel/dmesg* | sort | tail -10 | tr -d ']['"
	  log

	  log "pulp logs:"
	  log_cmd "egrep -i 'no space left on device' $base_dir/sos_commands/pulp/pulp-running_tasks -B 4 -A 5 | egrep 'description|code|start_time' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 'N;N;s/\n/ /g' | sort -k15 | tail -10"
	  log

	  log "foreman logs:"
	  log_cmd "egrep -hir 'No space left on device$' $base_dir/var/log/foreman-maintain | sort -k1M -k2h -k3h | tail -10"
	  log

	  log "insights logs:"
	  INSIGHTS_OUTPUT=`"egrep -i 'no space left on device' $base_dir/var/log/insights-client/insights-client.log* | egrep -v "{|}" | egrep -i '^20..\-..\-..' | sort | tail -5 | sed s'/\\n/\n/'g"`
	  log "$INSIGHTS_OUTPUT"
	  log "---"
	  log

	  log "// disk usage info"
	  log "awk '{ if (\$2!=0) print \$0 }' \$base_dir/df"
	  log "---"
	  log_cmd "awk '{ if (\$2!=0) print \$0 }' $base_dir/df | egrep --color=always \"^|nfs\""
	  log "---"
	  log

	  log "Note:  Putting pulp, mongodb or postgres storage on nfs mounts can degrade the Satellite server's performance, so look for that."

	  log "Note:  In Satellite 6.10 /var/cache/pulp was moved to /var/lib/pulp/tmp, /var/lib/pulp/content was removed, and /var/lib/pulp/published/yum/master/yum_distributor was replaced by obscured filenames in /var/lib/pulp/media/artifact/."
	  log

	  log "Note: During the upgrade process from 6.9 to 6.10, the directory '/var/lib/pulp/published/' will double in size.  Additionally, the contents of '/var/lib/mongodb/data/' will be imported into '/var/opt/rh/rh-postgresql12/lib/pgsql/data/' at 1.5x the original size of '/var/lib/mongodb/data/'."
	  log

	  log "// inode exhaustion info"
	  log "awk '{ if (\$2!=0) print \$0 }' \$base_dir/sos_commands/filesys/df_-ali_-x_autofs"
	  log "---"
	  log_cmd "awk '{ if (\$2!=0) print \$0 }' $base_dir/sos_commands/filesys/df_-ali_-x_autofs"
	  log "---"
	  log

          log "// read-only volumes"
          log "egrep \"/dev/sd|/dev/mapper\" \$base_dir/mount | grep -v rw"
          log "---"
          log_cmd "egrep \"/dev/sd|/dev/mapper\" $base_dir/mount | grep -v rw | egrep --color=always \"^|\/tmp\""
          log "---"

          log "Note:  The satellite-installer tool (because it uses puppet) can fail when /tmp and/or /var/tmp are mounted read-only, so look for that."
          log

          log "// check noexec property on tmp directories"
          log "egrep noexec -h \$base_dir/{mount,etc/fstab} | grep \/tmp"
          log "---"
          log_cmd "egrep noexec -h $base_dir/{mount,etc/fstab} | grep \/tmp"
          log "---"
          log


	  # i included stratis info here because stratis is _cool_
          if [ -d $base_dir/sos_commands/stratis ]; then
		      log "// stratis pool list"
		      log "cat \$base_dir/sos_commands/stratis/stratis_pool_list"
		      log "---"
		      log_cmd "cat $base_dir/sos_commands/stratis/stratis_pool_list"
		      log "---"
		      log

		      log "// stratis filesystem list"
		      log "cat \$base_dir/sos_commands/stratis/stratis_filesystem_list"
		      log "---"
		      log_cmd "cat $base_dir/sos_commands/stratis/stratis_filesystem_list"
		      log "---"
		      log

		      log "// stratis filesystems within /etc/fstab"
		      log "---"
		      STRATIS_UUIDS=`egrep -v '^Pool Name' $base_dir/sos_commands/stratis/stratis_filesystem_list | awk '{print $NF}' | tr '\n' '|' | rev | cut -c2- | rev`
		      log_cmd "egrep -i '^|stratis|$STRATIS_UUIDS' $base_dir/etc/fstab"
		      log "---"
		      log

		      log "// stratis messages errors"
		      log "egrep -i stratis \$base_dir/sysmgmt/messages"
		      log "---"
		      log_cmd "egrep -i $base_dir/sysmgmt/messages | tail -50"
		      log "---"
		      log

		      log "// stratis journal errors"
		      log "cat \$base_dir/sos_commands/stratis/journalctl_--no-pager_--unit_stratisd"
		      log "---"
		      log_cmd "cat $base_dir/sos_commands/stratis/journalctl_--no-pager_--unit_stratisd | tail -50"
		      log "---"
		      log
          fi

	  log "// logrotate entry for dynflow_executor.output"
	  log "grep dynflow_executor.output \$base_dir/etc/logrotate.d/foreman*"
	  log "---"
	  log_cmd "grep dynflow_executor.output $base_dir/etc/logrotate.d/foreman* 2>&1"
	  log "---"
	  log


          log_tee "## ntp info"
          log

                #SERVICE_NAME='ntpd|chronyd|systemd-timedatectl'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
		#IFS=$'\n'; NL=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sysmgmt/services.txt | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -');  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""${NL}""$i" | egrep .); fi; done; 
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log
                #log "ntp.conf:"
                #log_cmd "egrep ^server $base_dir/etc/ntp.conf 2>/dev/null | grep -v :\# | awk -F\"/\" '{print $NF}'"
                #log
                #log "chrony.conf:"
                #log_cmd "egrep ^server $base_dir/etc/chrony.conf 2>/dev/null | grep -v :\# | awk -F\"/\" '{print $NF}'"
                #log "---"
                #log

                SERVICE_NAME='ntpd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h 'ntpd|chronyd|systemd-timedatectl' $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
		log
                SERVICE_NAME='chronyd'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log
                SERVICE_NAME='systemd-timedatectl'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log
                log "ntp.conf:"
                log_cmd "egrep ^server $base_dir/etc/ntp.conf 2>/dev/null | grep -v :\# | awk -F\"/\" '{print $NF}'"
                log
                log "chrony.conf:"
                log_cmd "egrep ^server $base_dir/etc/chrony.conf 2>/dev/null | grep -v :\# | awk -F\"/\" '{print $NF}'"
                log "---"
                log


          log "// ntp errors"
          #log "egrep 'ntpd|chrony|sntp|timesync' \$base_dir/var/log/messages* | egrep -v 'source|starting|Frequency|HTTP\/1.1|pulp_database.units_rpm|mongod\.'"
	  log "egrep 'ntpd|chrony|sntp|timesync' \$base_dir/sysmgmt/messages | egrep -v 'source|starting|Frequency|HTTP\/1.1|pulp_database.units_rpm|mongod\.' | sed s'/#012/\n/'g"
          log "egrep -i 'skew|RES equals failed' \$base_dir/var/log/* | egrep -v anaconda"
          log "---"
          #log_cmd "egrep 'ntpd|chrony|sntp|timesync' $base_dir/var/log/messages* | egrep -v 'source|starting|Frequency|HTTP\/1.1|pulp_database.units_rpm|mongod\.' | egrep '^|offline|mongod'"
	  log_cmd "egrep 'ntpd|chrony|sntp|timesync' $base_dir/sysmgmt/messages | egrep -v 'source|starting|Frequency|HTTP\/1.1|pulp_database.units_rpm|mongod\.'"
          log
          log_cmd "egrep -i 'skew|RES equals failed' $base_dir/var/log/* | egrep -v 'BEGIN CERTIFICATE|^Binary|anaconda' | egrep -v 'HTTP\/1.1|mongod'"
          log "---"
          log


	  log_tee "## proxy info"
	  log

          log "// check /etc/environment"
          log "grep -i proxy \$base_dir/etc/environment"
          log "---"
          log_cmd "grep -i proxy $base_dir/etc/environment 2>&1"
          log "---"
          log

          log "// check the environment variables"
          log "grep -i proxy \$base_dir/environment"
          log "---"
          log_cmd "grep -i proxy $base_dir/environment 2>&1"
          log "---"
          log

	  log "// RHSM Proxy"
	  log "grep proxy \$base_dir/etc/rhsm/rhsm.conf | grep -v ^#"
	  log "---"
	  log_cmd "grep proxy $base_dir/etc/rhsm/rhsm.conf | grep -v ^#"
	  log "---"
	  log

	  log "// yum/dnf proxy"
	  log "grep proxy \$base_dir/etc/yum.conf \$base_dir/etc/dnf/dnf.conf | grep -v ^#"
	  log "---"
	  log_cmd "grep proxy $base_dir/etc/yum.conf $base_dir/etc/dnf/dnf.conf | grep -v ^#"
	  log "---"
	  log

	  log "// Satellite Proxy"
	  log "from files /etc/foreman-installer/scenarios.d/satellite-answers.yaml and \$base_dir/sos_commands/foreman/foreman_settings_table"
	  log "---"
	  log_cmd "grep -E '(^  proxy_url|^  proxy_port|^  proxy_username|^  proxy_password)' $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml} 2>/dev/null"
	  log
	  log_cmd "grep http_proxy $base_dir/sos_commands/foreman/foreman_settings_table 2>&1 | tr -d '+' | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -n"
	  log "---"
	  log

	  log "// Virt-who Proxy"
	  log "grep -i proxy \$base_dir/etc/sysconfig/virt-who"
	  log "---"
	  log_cmd "grep -i proxy $base_dir/etc/sysconfig/virt-who 2>&1"
	  log "---"
	  log

	  if [ -f $base_dir/bash_proxy ]; then
		log "// bash Proxy"
       		log "cat \$base_dir/bash_proxy"
          	log "---"
          	log_cmd "cat $base_dir/bash_proxy"
          	log "---"
          	log
	  fi

	  log_tee "## Network Information"
	  log

	  log "// ip address"
	  log "sort \$base_dir/ip_addr"
	  log "---"
	  log_cmd "sort $base_dir/ip_addr"
	  log "---"
	  log

          log "// check dhcp and dns interfaces in satellite-answers"
          log "grep _interface: \$base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml | egrep 'dhcp|dns'"
          log "---"
          log_cmd "grep _interface: $base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml | egrep 'dhcp|dns'"
          log "---"
          log

	  if [ -f "$base_dir/ping_hostname" ] || [ -f "$base_dir/ping_hostname_full" ]; then
		log "// ping hostname"
		log "---"
		log "cat \$base_dir/ping_hostname"
		log
		log "// ping full hostname"
		log "cat $base_dir/ping_hostname_full"
		log "---"
		log
	  fi

	  log "// hosts entries"
	  log "cat \$base_dir/etc/hosts"
	  log "---"
	  export GREP_COLORS='ms=01;33'
	  log_cmd "cat $base_dir/etc/hosts | egrep --color=always '^|$HOSTNAME|$IPADDRLIST'"
	  export GREP_COLORS='ms=01;31'
	  log "---"
	  log

	  log "// resolv.conf"
	  log "cat \$base_dir/etc/resolv.conf"
	  log "---"
	  log_cmd "cat $base_dir/etc/resolv.conf"
	  log "---"
	  log

          log "// firewall services"
          log "egrep 'iptables|firewalld' \$base_dir/sos_commands/systemd/systemctl_list-units \$base_dir/sos_commands/systemd/systemctl_list-unit-files"
          log "---"
          log_cmd "egrep 'iptables|firewalld' $base_dir/sos_commands/systemd/systemctl_list-units $base_dir/sos_commands/systemd/systemctl_list-unit-files"
          log "---"
          log

	  log "// firewalld settings"
	  log "sed -n '/(active)/,/^$/p' \$base_dir/sos_commands/firewalld/firewall-cmd_--list-all-zones"
	  log "---"
	  log_cmd "sed -n '/(active)/,/^$/p' $base_dir/sos_commands/firewalld/firewall-cmd_--list-all-zones | GREP_COLORS='ms=01;33' egrep --color=always '^|RH-Satellite-6|http|80\/tcp|https|443\/tcp|8443\/tcp|5646\/tcp|5647\/tcp|9090\/tcp' | GREP_COLORS='ms=01;96' egrep --color=always '^|ssh|22\/tcp|dns|53\/udp|53\/tcp| dhcp |67\/udp|69\/udp|5000\/tcp|8000\/tcp|8140\/tcp'"
	  log_cmd "egrep 'FirewallD is not running' $base_dir/sos_commands/firewalld/firewall-cmd_--list-all-zones'"
	  log "---"
	  log
	  log_cmd "echo 'Note:  Required ports:  80 (http), 443 (https), katello/qpidd (5646/5647), 8443 (registering through capsules, uploading facts), 9090 (capsule API)' | GREP_COLORS='ms=01;33' egrep --color=always ."
	  log_cmd "echo 'Note:  Optional ports:  22 (ssh), 5000 (compute resources), provisioning (53(dns)/67(dhcp)/69(TFTP)/8000 (iPXE)/8443), 8140 (puppet)' | GREP_COLORS='ms=01;96' egrep --color=always ."
	  log

	  log "// iptables extra line count"
	  log "egrep -vc '^$|^COMMAND|Chain|pkts' \$base_dir/sos_commands/networking/iptables_-vnxL"
	  log "---"
	  log_cmd "if [ -f $base_dir/sos_commands/networking/iptables_-vnxL ]; then egrep -vc '^$|^COMMAND|Chain|pkts' $base_dir/sos_commands/networking/iptables_-vnxL; else echo 'no iptables output found'; fi"
	  log "---"
	  log

	  log "Note:  If firewalld is running, then the iptables output should contain rules (roughly 30-40 on a Satellite 6.7 server).  If firewalld is not running and iptables still has rules defined, then the customer is likely using hand-crafted rules."

	  log

          log "// maintenance mode check"
	  log "egrep 'maintenance_mode' \$base_dir/var/log/foreman-maintain/foreman-maintain.log | tail"
	  #log "zgrep maintenance_mode \$base_dir/var/log/foreman-maintain/foreman-maintain.log* | sort -k2 | tail"
	  log "cat \$base_dir/sos_commands/networking/iptables_-vnxL | sed -n '/FOREMAN_MAINTAIN/,/^$/p'"
          log "---"
	  log_cmd "egrep 'maintenance_mode' $base_dir/sysmgmt/foreman-maintain.log* | sort -k2 -k3 | tail"
	  #log_cmd "zgrep maintenance_mode $base_dir/var/log/foreman-maintain/foreman-maintain.log* | sort -k2 | tail"
	  log
	  log_cmd "cat $base_dir/sos_commands/networking/iptables_-vnxL | sed -n '/FOREMAN_MAINTAIN/,/^$/p'"
          log "---"
          log

	  log "// current route"
	  log "cat \$base_dir/route"
	  log "---"
	  log_cmd "cat $base_dir/route"
	  log "---"
	  log

	  log_tee "## Environment"
	  log

	  log "// systemctl environment"
	  log "cat \$base_dir/sos_commands/systemd/systemctl_show-environment"
	  log
	  log_cmd "cat $base_dir/sos_commands/systemd/systemctl_show-environment"
	  log

	  log "// contents of /etc/environment"
	  log "cat \$base_dir/etc/environment"
	  log
	  log_cmd "cat $base_dir/etc/environment"
	  log


          log "// contents of /etc/locale.conf"
          log "cat \$base_dir/etc/locale.conf"
          log "---"
          log_cmd "cat $base_dir/etc/locale.conf"
          log "---"
          log

          log "// postgres locale"
          log "from file \$base_dir/var/lib/pgsql/data/postgresql.conf"
          log "---"
          log_cmd "egrep locale $base_dir/var/lib/pgsql/data/postgresql.conf"
          log "---"
          log

	  log_tee "## SELinux"
	  log


          log "// SELinux status"
          log "display SELinux status"
          log "---"
	  log_cmd "grep -v \# $base_dir/etc/selinux/config | grep ."
	  log
	  log_cmd "cat $base_dir/sos_commands/selinux/sestatus_-b | sed -n '/status/,/^$/p' | egrep ."
          log "---"
          log

	  log "// setroubleshoot package"
	  log "grep setroubleshoot \$base_dir/installed-rpms"
	  log "---"
	  log_cmd "grep setroubleshoot $base_dir/installed-rpms 2>&1"
	  log "---"
	  log

	  log "// SELinux denials"
	  log "grep for selinux denials"
	  log "---"
	  log "from /var/log/audit/audit.log:"
	  #log_cmd "tail -30 $base_dir/selinux_denials.log 2>/dev/null || grep -o denied.* $base_dir/var/log/audit/audit.log | sort -u | tail -100"
	  SE_DENIALS=`cat $base_dir/var/log/audit/* | sort -u | egrep '^type=(AVC|SELINUX)' | while read line; do time=\`echo $line | sed 's/.*audit(\([0-9]*\).*/\1/'\`; echo \`date -d @$time +'%Y-%m-%d.%H:%M'\` $line; done | awk '{$2=""; $3=""; $4=""; print $0}' | tail -1000`
	  log_cmd "echo -E \"$SE_DENIALS\" | egrep \"`date +'%Y' --date='-2 months'`|`date +'%Y'`\" | tail -30 | egrep denied | egrep --color=always '^|permissive=0|sidekiq|unix_stream_socket|connectto' | GREP_COLORS='ms=01;33' egrep --color=always '^|permissive=1'"
	  log
	  log "from /var/log/messages:"
	  #log_cmd "egrep -I 'avc:  denied|SELinux is preventing|setroubleshoot' $base_dir/var/log/messages* | egrep -v 'units_rpm|HTTP\/1.1|aide:' | sort -u | tail -30 | egrep --color=always '^|permissive=0|sidekiq|unix_stream_socket|connectto'"
          log_cmd "egrep -I 'avc:  denied|SELinux is preventing|setroubleshoot' $base_dir/sysmgmt/messages | egrep -v 'units_rpm|HTTP\/1.1|aide:' | sort -u | tail -30 | egrep --color=always '^|permissive=0|sidekiq|unix_stream_socket|connectto' | sed s'/#012/\n/'g | GREP_COLORS='ms=01;33' egrep --color=always '^|permissive=1'"
	  log "---"
	  log

	  if [ -f "$base_dir/foreman_filecontexts" ]; then
		log "// foreman file contexts"
		log "cat \$base_dir/foreman_filecontexts"
		log "---"
		log_cmd "cat $base_dir/foreman_filecontexts"
		log "---"
		log
	  fi

          log_tee "## fips mode"
          log

          log "// check for fips status"
	  log "cat \$base_dir/proc/sys/crypto/fips_enabled"
          log "egrep fips_enabled \$base_dir/var/log/foreman-installer/satellite* -h | egrep resolved"
          log "---"
	  log_cmd "echo fips_enabled flag:  \"`cat $base_dir/proc/sys/crypto/fips_enabled`\" | egrep --color=always '^|fips_enabled flag: 1'"
	  log
          log_cmd "egrep fips_enabled $base_dir/sysmgmt/{satellite.log,capsule.log,katello-installer.log} -h | egrep resolved | egrep --color=always '^|true'"
          log "---"
          log

          log "// fips in the logs"
	  log "egrep -hir 'fips mode|fips_enabled' \$base_dir/var/log/{secure*,rhsm,foreman-installer/satellite*} | egrep '^....-..-..' | sort -h"
          log "---"
	  log_cmd "egrep -hir 'fips mode|fips_enabled' $base_dir/var/log/{secure*,rhsm,foreman-installer/satellite*} | egrep '^....-..-..' | sort -h | head -25"
	  log "..."
          log_cmd "egrep -hir 'fips mode|fips_enabled' $base_dir/var/log/{secure*,rhsm,foreman-installer/satellite*} | egrep '^....-..-..' | sort -h | tail -25"
          log "---"
          log

	  log_tee "## cron"
	  log

                SERVICE_NAME='cron'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

	  log "// crontabs in /var/spool/cron"
	  log "ls -l \$base_dir/var/spool/cron/*"
	  log "---"
	  log_cmd "ls -l $base_dir/var/spool/cron/* 2>/dev/null || echo 'No cron files found in /var/spool/cron'"
	  log "---"
	  log

	  log "// checking the contents of crontabs in /var/spool/cron"
	  log "for b in \$(ls -1 \$base_dir/var/spool/cron/*); do echo; echo \$b; echo \"===\"; cat \$b; echo \"===\"; done"
	  log "---"
	  CRONRESULTS=`for b in $(ls -1 $base_dir/var/spool/cron/* 2>/dev/null); do echo; echo $b; echo "==="; cat $b; echo "==="; done`
	  log "$CRONRESULTS"
	  log "---"
	  log

	  log "// cron files in /etc"
	  log "---"
	  log_cmd "find $base_dir/etc/cron* -type f"
	  log "---"
	  log

	  log "// last 20 entries from foreman/cron.log"
	  log "tail -20 \$base_foreman/var/log/foreman/cron.log"
	  log "---"
	  log_cmd "tail -20 $base_foreman/var/log/foreman/cron.log 2>&1"
	  log "---"
	  log


          log_tee "## cockpit"
          log

          log "Cockpit is a web-based server administration tool sponsored by Red Hat.  It was included in Fedora 21 by default, and later in RHEL 8 (although it can be installed in RHEL 7).  Cockpit listens on port 9090 by default, and therefore it conflicts with the foreman-proxy service.  Cockpit can be reconfigured to use another port to prevent this conflict."
          log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep 'cockpit'`" ] || [ ! "`egrep -i cockpit $base_dir/installed-rpms $base_dir/sysmgmt/journalctl.log $base_dir/sysmgmt/messages 2>/dev/null | egrep -v 'units_rpm|\.rpm'`" ]; then

                log "cockpit not found"
                log

          else

                #SERVICE_NAME='cockpit'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='cockpit'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// log errors for cockpit-ws"
                if [ -f "$base_dir/sysmgmt/journal.log" ]; then
                        log "from journalctl_--no-pager_--catalog_--boot and messages"
                        log "---"
                        log_cmd "grep 'cockpit-ws' $base_dir/sysmgmt/journal.log | egrep -v 'units_rpm command|units_package_group|pulp_streamer|nectar.download' | tail -30 | cut -c -10240"
                elif [ -f "$base_dir/var/log/messages" ]; then
                        log "from /var/log/messages"
                        log "---"
                        log_cmd "grep 'cockpit-ws' $base_dir/sysmgmt/messages | grep -v 'units_rpm command' | tail -30 | cut -c 10240"
                else
                        log "---"
                        log "neither \$base_dir/sysmgmt/journal.log nor /var/log/messages found"
                fi
                log "---"
                log

          fi


	  log_tee "## /var/log/messages"
	  log


	  log "// errors in messages file (uniq, no goferd)"
	  log "grep messages files for errors"
	  log "---"
	  #{ for mylog in `ls -rt $base_dir/var/log/messages* 2>/dev/null`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | grep -v 'goferd:' | egrep "`date +'%Y' --date='-2 months'`|`date +'%Y'`" | uniq -f 3 | tail -300 | cut -c 10240 | sed 's/^[ \t]*//;s/[ \t]*$//' | uniq >> $FOREMAN_REPORT
	  egrep ERROR $base_dir/sysmgmt/messages | egrep -v 'goferd:' | egrep "`date +'%Y' --date='-2 months'`|`date +'%Y'`" | uniq -f 3 | tail -300 | cut -c 10240 | sed 's/^[ \t]*//;s/[ \t]*$//' | uniq >> $FOREMAN_REPORT
	  log "---"
	  log


	  log_tee " "
	  log


	  log_tee "## Repos and Packages"
	  log

	  log "// enabled repos"
	  log "cat \$base_dir/sos_commands/yum/yum_-C_repolist"
	  log "---"
	  log_cmd "cat $base_dir/sos_commands/yum/yum_-C_repolist | egrep -i --color=always \"^|epel|fedora\""
	  log "---"
	  log

          log "// release version (for version locking)"
          log "jq '.' \$base_dir/var/lib/rhsm/cache/releasever.json"
          log "cat \$base_dir/etc/yum/vars/releasever 2>/dev/null"
          log "cat \$base_dir/sos_commands/sos_commands/subscription_manager/subscription-manager_release_--show 2>/dev/null"
          log "---"
          log_cmd "jq '.' $base_dir/var/lib/rhsm/cache/releasever.json 2>/dev/null"
          log "---"
          log_cmd "cat $base_dir/etc/yum/vars/releasever 2>/dev/null;echo"
          log "---"
          log_cmd "cat $base_dir/sos_commands/sos_commands/subscription_manager/subscription-manager_release_--show 2>/dev/null"
          log "---"
          log

          log "// available releases"
          log "cat \$base_dir/sos_commands/subscription_manager/subscription-manager_release_--list"
          log "---"
          log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_release_--list"
          log "---"
          log

          log "// available repositories listed in rhsm.log"
          log "egrep '\[id:' \$base_dir/var/log/rhsm/rhsm.log | sort -u"
          log "---"
          log_cmd "egrep '\[id:' $base_dir/var/log/rhsm/rhsm.log | sort -u"
          log "---"
          log

          log "// yum/dnf exclusions"
          log "egrep -r exclude \$base_dir/etc/yum* \$base_dir/etc/dnf/dnf.conf"
          log "---"
	  log_cmd "egrep -r exclude $base_dir/etc/yum* $base_dir/etc/dnf/dnf.conf"
          log "---"
          log

          log "// disabled modules"
          log "egrep '\[x|x\]' \$base_dir/sos_commands/dnf/dnf_--assumeno_module_list"
          log "---"
          log_cmd "egrep '\[x|x\]' \$base_dir/sos_commands/dnf/dnf_--assumeno_module_list | sed 's/^[ \t]*//;s/[ \t]*$//'"
          log "---"
          log

          log "// contents of /etc/yum/pluginconf.d/versionlock.list"
          log "cat \$base_dir/etc/yum/pluginconf.d/versionlock.list"
          log "---"
          log_cmd "cat $base_dir/etc/yum/pluginconf.d/versionlock.list || echo file '/etc/yum/pluginconf.d/versionlock.list' is absent"
          log "---"
          log


	  log "// all installed satellite packages"
	  log "egrep \"satellite|spacewalk|spacecmd\" \$base_dir/installed-rpms"
	  log "---"
	  if [ "$HOSTNAME" ]; then
		log_cmd "egrep \"satellite|spacewalk|spacecmd\" $base_dir/installed-rpms 2>&1 | egrep -v $HOSTNAME"
	  else
		log_cmd "egrep \"satellite|spacewalk|spacecmd\" $base_dir/installed-rpms 2>&1"
	  fi
	  log "---"
	  log

	  log "// packages provided by 3rd party vendors"

	  log "show third-party packages from package-data and/or 3rd_party files"
	  log "---"
	  log_cmd "egrep -hv 'Red Hat|^$HOSTNAME|^gpg\-pubkey\-' $base_dir/sos_commands/rpm/package-data | cut -f1,4 | sort -k2 | egrep -i --color=always '^|$SATPACKAGES|Fedora|Kojii|CentOS|syslog-ng|katello-ca-consumer'"
	  log_cmd "cat $base_dir/3rd_party 2>/dev/null | sort -k2 | egrep -i --color=always '^|$SATPACKAGES|Fedora|Kojii|CentOS|syslog-ng|katello-ca-consumer'"
	  log "---"
	  log

	  log "Note:  Third party packages sometimes cause issues for Satellite servers.  The EPEL repositories are known to have newer versions of some Satellite packages (which will be signed in the above list by \"Fedora\"), as is the upstream Foreman project (which will be signed by \"Koji\").  Antivirus scanners can sometimes prevent RPM installations, causing satellite-installer to fail."

	  log


	  log "// yum history"
	  log "grep . \$base_dir/sos_commands/yum/yum_history | sed 's/^[ \t]*//;s/[ \t]*$//' | tr -s \"[:blank:]\""
	  log "---"
	  log_cmd "grep . $base_dir/sos_commands/yum/yum_history | sed 's/^[ \t]*//;s/[ \t]*$//' | egrep -i --color=always \"^|$SATPACKAGES\" | tr -s \"[:blank:]\""
	  log "---"
	  log

	  if [ ! -f $base_dir/var/log/dnf.rpm.log ]; then
	  	log "// yum.log info"
	  	log "tail -300 \$base_dir/var/log/yum.log"
	  	log "---"
	  	log_cmd "tail -300 $base_dir/var/log/yum.log | egrep -i --color=always '^|$SATPACKAGES'"
	  	log "---"
	  	log
	  else
                log "// dnf.rpm.log info"
                log "egrep -v logging \$base_dir/var/log/dnf.rpm.log | tail -300"
                log "---"
                log_cmd "egrep -v logging $base_dir/var/log/dnf.rpm.log | tail -300 | egrep -i --color=always '^|$SATPACKAGES'"
                log "---"
                log
	  fi

	  log "// yum activity from lvmdump messages"
	  log "grep yum \$base_dir/sos_commands/lvm2/lvmdump/messages"
	  log "---"
	  log_cmd "grep yum $base_dir/sos_commands/lvm2/lvmdump/messages 2>&1"
	  log "---"
	  log


	  log_tee "## Subscriptions"
	  log

	  log "// subscription identity"
	  log "cat \$base_dir/sos_commands/subscription_manager/subscription-manager_identity"
	  log "---"
	  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_identity"
	  log "---"
	  log

          ORG=''; LCE=$ORG; CV=$ORG
          COUNT=0;for i in `grep baseurl $base_dir/etc/yum.repos.d/redhat.repo 2>/dev/null | head -1 | sed s'/baseurl = https:\/\///'g | tr '/' ' '`; do COUNT=`expr $COUNT + 1`;if [ "$i" == "content" ] || [ "$i" == "cdn.redhat.com" ]; then break; elif [ "$COUNT" -eq 4 ]; then ORG=$i;  elif [ "$COUNT" -eq 5 ]; then LCE=$i;elif [ "$COUNT" -eq 6 ]; then CV=$i;fi; done
          if [ "$ORG" ]; then
		log "// traces of subscription identity in redhat.repo file (useful in RHEL 6)"
		log "---"
		log_cmd "echo org ID:  $ORG"
		log_cmd "echo environment name:  $LCE/$CV"
		log "---"
		log
	  fi

          log "// syspurpose"
          log "cat \$base_dir/etc/rhsm/syspurpose/syspurpose.json"
          log "---"
          log_cmd "cat $base_dir/etc/rhsm/syspurpose/syspurpose.json"
	  log
          log "---"
          log

	  log "// list rhsm targets"
	  log "egrep \"baseurl\" \$base_dir/etc/rhsm/rhsm.conf*"
	  log "---"
	  log_cmd "egrep \"baseurl\" $base_dir/etc/rhsm/rhsm.conf*"
	  log "---"
	  log

	  log "// subsman list installed"
	  log "cat \$base_dir/sos_commands/subscription_manager/subscription-manager_list_--installed"
	  log "---"
	  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--installed"
	  log "---"
	  log

	  log "// subsman list consumed"
	  log "cat \$base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
          log "---"
	  log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
	  log "---"
	  log

          log "// check for simple content access (SCA)"
          log "jq '.' \$base_dir/var/lib/rhsm/cache/content_access_mode.json | egrep 'org_environment'"
          log "egrep 'Content Access' \$base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot | tail"
          log "---"
          log_cmd "jq '.' $base_dir/var/lib/rhsm/cache/content_access_mode.json | egrep 'org_environment'"
          log_cmd "egrep 'Content Access' $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot | egrep -v 'pushcount' | tail"
          log "---"
          log


          log "// number of CPUs"
          log "egrep -hc processor \$base_dir/proc/cpuinfo"
          log "---"
          log_cmd "if [ -f $base_dir/sos_commands/processor/lscpu ]; then egrep '^CPU\(s\):' $base_dir/sos_commands/processor/lscpu; elif [ -f $base_dir/proc/cpuinfo ]; then egrep -hc processor $base_dir/proc/cpuinfo; elif [ -f $base_dir/procs ]; then cat $base_dir/procs; fi"
          log "---"
          log

	  log "// number of sockets"
	  log "grep ^Socket \$base_dir/sos_commands/processor/lscpu"
	  log "---"
	  log_cmd "grep ^Socket $base_dir/sos_commands/processor/lscpu"
	  log "---"
	  log

	  log "// available subscriptions"
          log "egrep '^$|^Subscription Name:|^Pool|^Provides:' \$base_dir/sos_commands/subscription_manager/subscription-manager_list_--all_--available"
          log "---"
          log_cmd "egrep '^$|^Subscription Name:|^Pool|^Provides:' $base_dir/sos_commands/subscription_manager/subscription-manager_list_--all_--available | sed 's/^[ \t]*//;s/[ \t]*$//' | egrep -v :$"
          log "---"
          log


	  log_tee "## /var/log/rhsm/rhsm.log"
	  log

          log "// subsman list consumed"
          log "cat \$base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
          log "---"
          log_cmd "cat $base_dir/sos_commands/subscription_manager/subscription-manager_list_--consumed"
          log "---"
          log

          log "// check for simple content access (SCA)"
          log "jq '.' \$base_dir/var/lib/rhsm/cache/content_access_mode.json | egrep 'org_environment'"
          log "egrep 'Content Access' \$base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot | tail"
          log "---"
          log_cmd "jq '.' $base_dir/var/lib/rhsm/cache/content_access_mode.json | egrep 'org_environment'"
          log_cmd "egrep 'Content Access' $base_dir/sos_commands/logs/journalctl_--no-pager_--catalog_--boot | egrep -v 'pushcount' | tail"
          log "---"
          log

	  log "// RHSM errors and warnings"
	  log "egrep 'ERROR|WARNING' \$base_dir/var/log/rhsm/rhsm.log"
	  log "---"
	  log_cmd "egrep 'ERROR|WARNING' $base_dir/var/log/rhsm/rhsm.log | egrep -v 'virt-who|logging already initialized' | tail -100"
	  log "---"
	  log

          log "// CDN connectivity check"
          log "cat \$base_dir/sos_commands/subscription_manager/curl_-vv_https_..subscription.rhn.redhat.com_443.subscription_--cacert_.etc.rhsm.ca.redhat-uep.pem"
          log "---"
          log_cmd "cat $base_dir/sos_commands/subscription_manager/curl_-vv_https_..subscription.rhn.redhat.com_443.subscription_--cacert_.etc.rhsm.ca.redhat-uep.pem"
          log "---"
          log


	  log "// subscription-manager activity from lvmdump messages"
	  log "grep subscription-manager \$base_dir/sos_commands/lvm2/lvmdump/messages"
	  log "---"
	  log_cmd "grep subscription-manager $base_dir/sos_commands/lvm2/lvmdump/messages 2>&1"
	  log "---"
	  log

	  log_tee
	  log

          log_tee "## Satellite Upgrade"
          log

	  if [ -f "$base_dir/sos_commands/dnf/dnf_--assumeno_module_list" ]; then
		log "// disabled modules"
		log "egrep '^Name|satellite' \$base_dir/sos_commands/dnf/dnf_--assumeno_module_list"
		log "---"
		log_cmd "egrep '^Name|satellite' $base_dir/sos_commands/dnf/dnf_--assumeno_module_list"
		log "---"
		log
	  fi

          log "// recent exit codes from satellite-installer"

          log "grepping satellite and capsule files in foreman-installer directory for upgrade statuses"
          log "---"

          export GREP_COLORS='ms=01;33'
          #cmd_output_timestamps=$(egrep -ir -h "Exit with status code|command with arguments|with args|Upgrade completed|target-version|capsule-certs-generate|Prepare content|additional free space|migration statistics|" $base_dir/sysmgmt/{capsule.log,foreman-maintain.log,production.log,satellite.log} 2>/dev/null | egrep '\-' | sed s'/\[  INFO //'g | sed s'/\[ INFO //'g | sed s'/\[DEBUG //'g | sed s'/^., \[//'g | sort -n | tail -60)

	  cmd_output_timestamps=$(egrep -ir -h "Exit with status code|command with arguments|with args|Upgrade completed|target-version|capsule-certs-generate" $base_dir/sysmgmt/{capsule.log,foreman-maintain.log,production.log,satellite.log} 2>/dev/null | egrep "\-" | sed s'/\[  INFO //'g | sed s'/\[ INFO //'g | sed s'/\[DEBUG //'g | sed s'/^., \[//'g | sed s'/T0/ 0/'g | sed s'/T1/ 1/'g | sed s'/T2/ 2/'g | sort -n | egrep -v service | tail -100)

	  cmd_output_migration_stats=$(egrep -hi 'Migration Summary|^Migrated|^Estimated migration time|^You will need|additional free space' $base_dir/sysmgmt/foreman-maintain.log 2>/dev/null | egrep 'Migration Summary' -A 10 | tail -14 | sed -n '/Migration Summary/,/^$/p')

          log "$cmd_output_timestamps"
	  log
	  log "$cmd_output_migration_stats"
          export GREP_COLORS='ms=01;31'

          log "---"
          log

          log "Note:  Exit codes of 0 indicate success, and exit codes of 2 indicate success accompanied by changes to Satellite."
          log

          #if [ -f "$base_foreman/var/log/foreman-installer/satellite.log" ]; then
          log "// Number of ERROR lines in foreman-installer/satellite.log"
          log "egrep -hc '^\[ERROR' \$base_dir/sysmgmt/{satellite.log,capsule.log,katello-installer.log}"
          #log "---"
          #log_cmd "if [ -f $base_foreman/var/log/foreman-installer/satellite.log ]; then grep '^\[ERROR' $base_foreman/var/log/foreman-installer/satellite.log 2>/dev/null | wc -l; fi"
	  log_cmd "egrep -hc '^\[ERROR' $base_dir/sysmgmt/{satellite.log,capsule.log,katello-installer.log}"
          log "---"
          log
          #fi

          log "// Last 20 lines from upgrade log"
          log "egrep -v \"\/opt|\]$|\.rb\:\" \$base_foreman/var/log/foreman-installer/{satellite.log,capsule.log} | tail -20"
          log "---"
          export GREP_COLORS='ms=01;33'
          log_cmd "egrep -v \"\/opt|\]$|\.rb\:\" $base_dir/sysmgmt/{satellite.log,capsule.log} 2>&1 -h | sort -h | tail -20 | egrep --color=always '^|Exit with status code|Complete'"
          export GREP_COLORS='ms=01;31'
          log "---"
          log

          log "// check for purge_configs setting"
          log "egrep purge_configs \$base_foreman/etc/foreman-installer/custom-hiera.yaml"
          log "---"
          log_cmd "egrep purge_configs $base_foreman/etc/foreman-installer/custom-hiera.yaml"
          log "---"
          log


	  log_tee
	  log


	  log_cmd "echo ================================================ | grep --color=always \="
	  log
	  log "Satellite Components"
	  log "(capsule components are in green)"
	  log
	  log_cmd "echo ================================================ | grep --color=always \="
	  log

	  export GREP_COLORS='ms=01;32'
	  log_cmd "echo 'httpd                            qdrouterd' | egrep --color=always '^|.'"
	  log_cmd "echo '  |                                  |' | egrep --color=always '^|.'"
	  log_cmd "echo '  |      celery     mongodb       qpidd      squid  redis' | egrep --color=always '^|.'"
	  log_cmd "echo '  |           |          |           |         |      |' | egrep --color=always '^|.'"
	  log_cmd "echo '  \-pulp -----/----------/-----------/---------/------/' | egrep --color=always '^|.'"
	  log_cmd "echo '  |' | egrep --color=always '^|.'"
          log_cmd "echo '  \-smart_proxy_dynflow_core' | egrep --color=always '^|.'"
	  log "  |"
	  log "  \-passenger/puma"
	  log "        |"
          log_cmd "echo '        \-puppet3       postgreSQL                 tomcat' | egrep --color=always '^|puppet3|postgreSQL'"
	  log "        |                |   |                       |"
	  log "        \-foreman -------/   \---------candlepin-----/"
	  log "            |"
	  log "            \-katello, dynflow, virt-who, subscription watch"
	  log
	  log_cmd "echo 'puppet4+' | egrep --color=always '^|.'"
	  log
	  log
	  export GREP_COLORS='ms=01;31'


	  log_tee "## Satellite Services"
	  log

	  if [ "`egrep -i 'satellite-6|satellite-cli' $base_dir/installed-rpms 2>/dev/null | head -1`" ]; then

		log "// hammer ping output"
		log "cat \$base_dir/sos_commands/foreman/hammer_ping"
		log "---"
		log_cmd "cat $base_dir/sos_commands/foreman/hammer_ping | egrep --color=always '^|FAIL' | GREP_COLORS='ms=01;33' egrep --color=always '^|\[OK\]' | egrep --color=always '^|more service\(s\) failed\, but not shown:'"
		log "---"
		log

	  fi

	  if [ -e $base_dir/sos_commands/systemd/systemctl_status_--all ]; then
            log "// condensed satellite service status"
            log "grepping files foreman-maintain_service_status and systemctl_status_--all"
            log "---"
	    log "egrep '\.service -|Loaded:|Active:|^$' \$base_dir/sos_commands/systemd/systemctl_status_--all | egrep '\.service -' -A 2 | egrep -A 2 '\* httpd.service|\* pulp|\* qdrouterd|\* qpidd|\* squid|\* redis|\* virt-who|\* smart|\* puppet|\* postgres|\* rh-postgres|\* tomcat|\* foreman|\* gofer|\* mongo|\* dynflow|\* osbuild-|\* elasticsearch'"
            log
	    #log_cmd "egrep '\.service -|Loaded:|Active:|^$' $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '\.service -' -A 2 | egrep -A 2 '\* httpd.service|\* pulp|\* qdrouterd|\* qpidd|\* squid|\* redis|\* virt-who|\* smart|\* puppet|\* postgres|\* rh-postgres|\* tomcat|\* foreman|\* gofer|\* mongo|\* dynflow|\* osbuild-|\* elasticsearch' | egrep --color=always '^|failed|inactive|activating|deactivating|masked'"
	    log_cmd "egrep '\.service -|Loaded:|Active:|^$' $base_dir/sysmgmt/services.txt | egrep '\.service -' -A 2 | egrep -A 2 '\* httpd.service|\* pulp|\* qdrouterd|\* qpidd|\* squid|\* redis|\* virt-who|\* puppet|\* postgres|\* rh-postgres|\* tomcat|\* foreman|\* gofer|\* mongo|\* rh-mongodb34-mongod|\* dynflow|\* osbuild-|\* elasticsearch' | egrep --color=always '^|failed|inactive|activating|deactivating|masked'"
            log "---"
            log
	  elif [ -e $base_dir/chkconfig ]; then

            log "// condensed satellite service status"
            log "grepping output of chkconfig command"
            log "---"
	    log_cmd "egrep -h 'httpd.service|pulp|qdrouterd|qpidd|squid|redis|virt-who|puppet|postgres|tomcat|foreman|gofer|mongo|dynflow|osbuild|elasticsearch' $base_dir/chkconfig"
            log "---"
            log

	  fi

	  if [ -f "$base_dir/sos_commands/foreman/foreman-maintain_service_status" ]; then


	    log "// satellite service status"
	    log "from file $base_dir/sos_commands/foreman/foreman-maintain_service_status"
	    log "---"
	    log_cmd "cat $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep -v 'pulp_database.units_rpm' | sed '/BEGIN CERTIFICATE/,/\"/d' | sed '/BEGIN PRIVATE KEY/,/\"/d' | tr '\r' '\n' | sed s'/\*/\n\*/'g | egrep -v '{|}|displaying|^\||^\/|^\\|^\-' | uniq | egrep -i --color=always '^|failed|inactive|activating|deactivating|masked|error|alert|crit|warning|signal=KILL' | GREP_COLORS='ms=01;33' egrep --color=always '^|\[OK\]|Active:|All services are running'"
	    log "---"
	    log

            log "// listening services"
            log "grepping netstat_-W_-neopa file for services listening on the network"
            log "---"
            log_cmd "egrep '^Active|^Proto|LISTEN' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | sort -k 1,8"
            log "---"
            log

	    log_tee " "


	  elif [ ! -e $base_dir/sos_commands/systemd/systemctl_status_--all ]; then

		log "no satellite services found"

	  fi

	  log




          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## goferd (capsules and hosts only)' | grep --color=always \#"
          echo '## goferd (capsules and hosts only)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

          log "// installed katello-agent and/or gofer"
          log "from file $base_dir/installed-rpms"
          log "---"
          log_cmd "grep -E '(^katello-agent|^gofer|^katello-host)' $base_dir/installed-rpms 2>&1"
          log "---"
          log


	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt | egrep goferd`" ] || [ ! "`egrep -i goferd $base_dir/chkconfig`" ]; then

		nop=1

	  else


                #SERVICE_NAME='goferd'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
		#IFS=$'\n'; NL=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sysmgmt/services.txt | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -');  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""${NL}""$i" | egrep .); fi; done; 
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='goferd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// goferd packages"
                log "egrep 'gofer|proton' $base_dir/sos_commands/yum/yum_list_installed"
                log "---"
                log_cmd "egrep 'gofer|proton' $base_dir/sos_commands/yum/yum_list_installed"
                log "---"
                log

            	log "// are katello/gofer listening?"
            	log "grepping netstat_-W_-neopa file for katello-agent port 5646 and goferd port 5647"
            	log "---"
            	log_cmd "egrep '^Active|^Proto|\:5646|\:5647' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
            	log "---"
            	log

                log "// is a goferd heartbeat configured?"
                log "egrep ^heartbeat \$base_dir/etc/gofer/plugins/katello.conf"
                log "---"
                log_cmd "egrep ^heartbeat $base_dir/etc/gofer/plugins/katello.conf"
                log "---"
                log

		log "// goferd errors in messages file (last 100)"
		log "grep messages files for errors"
		log "---"
		#{ for mylog in `ls -rt $base_dir/var/log/messages* 2>/dev/null`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | egrep 'ERROR|WARNING' | grep 'goferd:' | tail -100 &>> $FOREMAN_REPORT
		log_cmd "egrep 'ERROR|WARNING' $base_dir/sysmgmt/messages | egrep 'goferd:' | tail -100"
		log "---"
		log

	  fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## postgres' | grep --color=always \#"
	  echo '## postgres' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

            log "PostgreSQL is used by Foreman and Candlepin to store records related to registered content hosts, subscriptions, jobs, and tasks. Over time, PostgreSQL accumulates enough data to cause queries to slow relative to the speeds achievable in a fresh installation."
            log
            log "Note:  Prior to Satellite 6.10, capsule servers should have packages postgresql and postgresql-lib, but not postgresql-server."
            log

	  if [ "`egrep ^postgresql $base_dir/installed-rpms`" ]; then
                log "// installed postgres packages"
                log "egrep ^postgresql \$base_dir/installed-rpms"
                log "---"
                log_cmd "egrep ^postgresql $base_dir/installed-rpms"
                log "---"
                log
	  fi

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep postgres`" ] || [ ! "`egrep -i postgres $base_dir/chkconfig $base_dir/sos_commands/process/ps_auxwww 2>/dev/null | head -1`" ] && [ ! -d "$base_foreman/var/lib/pgsql" ] && [ ! -d "$base_foreman/var/opt/rh/rh-postgresql12" ] && [ ! -d "$base_dir/sos_commands/postgresql" ]; then

		log "postgres not found"
		log

	  else


                #SERVICE_NAME='postgres'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
		#IFS=$'\n'; NL=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sysmgmt/services.txt | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -');  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""${NL}""$i" | egrep .); fi; done; 
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='postgres'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                SERVICE_NAME='rh-postgresql12-postgresql'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// is postgres listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep '^Active|^Proto|postgres' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// postgres storage consumption"
		log "cat \$base_dir/sos_commands/postgresql/du_-sh_.var.lib.pgsql \$base_dir/sos_commands/postgresql/du_-sh_.var..opt.rh.rh-postgresql12.lib.pgsql"
		log "---"
		#log_cmd "cat $base_dir/sos_commands/postgresql/du_-sh_.var.lib.pgsql $base_dir/sos_commands/postgresql/du_-sh_.var..opt.rh.rh-postgresql12.lib.pgsql 2>/dev/null | sed s'/\/var\/lib\/pgsql/\/var\/lib\/pgsql    # pre-6.8/'g | sed s'/\/rh-postgresql12\/lib\/pgsql/\/lib\/pgsql    # post-6.8/'g"

		log_cmd "cat $base_dir/sos_commands/postgresql/du_-sh_.var.lib.pgsql $base_dir/sos_commands/postgresql/du_-sh_.var..opt.rh.rh-postgresql12.lib.pgsql 2>/dev/null | sed s'/\/var\/lib\/pgsql/\/var\/lib\/pgsql    # pre-6.8 or on RHEL8/'g | sed s'/rh-postgresql12\/lib\/pgsql/rh-postgresql12\/lib\/pgsql    # post-6.8 on RHEL7/'g"
		log "---"
		log

		log "// postgres idle process (everything)"
		log "egrep -hc ^postgres \$base_dir/ps | grep idle$"
		log "---"
		log_cmd "if [ -f $base_dir/ps ]; then egrep -hc ^postgres $base_dir/ps 2>&1 | grep idle$; fi"
		log "---"
		log

		log "// hugepages tuning settings"
		log "---"
		log_cmd "grep hugepages $base_dir/etc/default/grub;if [ \"`grep hugepages $base_dir/etc/tuned/* 2>/dev/null`\"]; then echo; grep hugepages $base_dir/etc/tuned/* 2>/dev/null; echo active tuned profile; cat $base_dir/sos_commands/tuned/tuned-adm_active; fi"
		log "---"
		log

		if [ -f "$base_dir/sos_commands/katello/db_table_size" ]; then

                        log "// top foreman tables consumption"
                        log "head -n30 \$base_dir/sos_commands/katello/db_table_size"
                        log "---"
                        log_cmd "head -n30 $base_dir/sos_commands/katello/db_table_size 2>/dev/null"
                        log "---"
                        log

		elif [ -f "$base_dir/sos_commands/foreman/foreman_db_tables_sizes" ] || [ -f "$base_dir/sos_commands/candlepin/candlepin_db_tables_sizes" ]; then

                        log "// top foreman tables consumption"
                        log "head -n30 \$base_dir/sos_commands/foreman/foreman_db_tables_sizes"
                        log "---"
                        log_cmd "head -n30 $base_dir/sos_commands/foreman/foreman_db_tables_sizes 2>/dev/null"
                        log "---"
                        log

                        log "// top candlepin tables consumption"
                        log "head -n30 \$base_dir/sos_commands/candlepin/candlepin_db_tables_sizes"
                        log "---"
                        log_cmd "head -n30 $base_dir/sos_commands/candlepin/candlepin_db_tables_sizes 2>/dev/null"
                        log "---"
                        log

		fi

                log "// postgres locale"
                log "from file \$base_dir/var/lib/pgsql/data/postgresql.conf"
                log "---"
                log_cmd "egrep locale $base_dir/var/lib/pgsql/data/postgresql.conf"
                log "---"
                log

		if [ ! -f "$base_dir/sos_commands/postgresql/du_-sh_.var..opt.rh.rh-postgresql12.lib.pgsql" ] && [ -d "$base_foreman/var/lib/pgsql/data" ] && [ ! -d "$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data" ]; then

			log "// pre-Satellite 6.8, or 6.11+ on RHEL 8"
			log

			log "// Current Configuration"
			log "grep -v -h \# \$base_foreman/var/lib/pgsql/data/postgresql.conf | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
			log "---"
			log_cmd "grep -v -h \# $base_foreman/var/lib/pgsql/data/postgresql.conf 2>/dev/null | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
			log
			log "---"
			log

			log "// postgres configuration"
			log "grep -h 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target\|autovacuum_cost_limit\|effective_cache_size' \$base_dir/var/lib/pgsql/data/postgresql.conf | grep -v '^#'"
			log "---"
			log_cmd "grep -h 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target\|autovacuum_cost_limit\|effective_cache_size' $base_dir/var/lib/pgsql/data/postgresql.conf 2>/dev/null | grep -v '^#' | egrep --color=always '^|autovacuum_cost_limit'"
			log "---"
			log
			log "Note:  The parameters checkpoint_segment and autovacuum_cost_limit can cause errors upgrading to Satellite 6.7"
			log


			#if [ -d $base_dir/var/lib/pgsql/data/pg_log ]; then

			#	log "// deadlocks"
			#	log "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log"
			#	log "---"
			#	log_cmd "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log | grep -v '[acpi]'"
			#	log "---"
			#	log

			#	log "// deadlock count"
			#	log "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
			#	log "---"
			#	log_cmd "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
			#	log "---"
			#	log

			#	log "// ERROR count"
			#	log "grep -h -i ERROR \$base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
			#	log "---"
			#	log_cmd "grep ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
			#	log "---"
			#	log

			#	log "// ERRORs (filtered)"
			#	log "grep -h -i ERROR \$base_foreman/var/lib/pgsql/data/pg_log/*.log"
			#	log "---"
			#	log_cmd "grep -h ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | tail -100 | sort -n | egrep -v '{|}|katello_rpms.filename' | cut -c -10240 | egrep 'katello_docker_meta_tags'"
			#	log "---"
			#	log

			#fi

		#else
		fi

                if [ -d $base_dir/var/lib/pgsql/data/pg_log ]; then

                        log "// deadlocks"
                        log "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log"
                        log "---"
                        log_cmd "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log | grep -v '[acpi]'"
                        log "---"
                        log

                        log "// deadlock count"
                        log "grep -h -i deadlock \$base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
                        log "---"
                        log_cmd "grep -h -i deadlock $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
                        log "---"
                        log

                        log "// ERROR count"
                        log "grep -h -i ERROR \$base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
                        log "---"
                        log_cmd "grep ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | wc -l"
                        log "---"
                        log

                        log "// ERRORs (filtered)"
                        log "grep -h -i ERROR \$base_foreman/var/lib/pgsql/data/pg_log/*.log"
                        log "---"
                        log_cmd "grep -h ERROR $base_foreman/var/lib/pgsql/data/pg_log/*.log | tail -100 | sort -n | egrep -v '{|}|katello_rpms.filename' | cut -c -10240 | egrep 'katello_docker_meta_tags'"
                        log "---"
                        log

                fi

		if [ -d "$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data" ]; then

			log
			log "// Satellite 6.8 or later on RHEL 7"
			log

			log "// Current Configuration"
			log "grep -v -h \# \$base_dir/var/opt/rh/rh-postgresql12/data/postgresql.conf | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
			log "---"
			log_cmd "grep -v -h \# $base_dir/var/opt/rh/rh-postgresql12/data/postgresql.conf 2>/dev/null | grep -v ^$ | grep -v -P ^\"\\t\\t\".*#"
			log "---"
			log

			log "// postgres configuration"
			log "grep -h 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target\|effective_cache_size\|autovacuum_vacuum_cost_limit' \$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/postgresql.conf | grep -v '^#'"
			log "---"
			log_cmd "grep -h 'max_connections\|shared_buffers\|work_mem\|checkpoint_segments\|checkpoint_completion_target\|effective_cache_size\|autovacuum_vacuum_cost_limit' $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/postgresql.conf 2>/dev/null | grep -v '^#'"
			log "---"
			log

			log "// deadlocks"
			log "grep -h -i deadlock \$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log"
			log "---"
			log_cmd "grep -h -i deadlock $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | grep -v '[acpi]'"
			log "---"
			log

			log "// deadlock count"
			log "grep -h -i deadlock \$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | wc -l"
			log "---"
			log_cmd "grep -h -i deadlock $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | wc -l"
			log "---"
			log

			log "// ERRORs (filtered)"
			log "grep -h -i ERROR \$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log"
			log "---"
			log_cmd "grep -h -i ERROR $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | egrep -v '{|}|katello_rpms.filename' | tail -100 | sort -n | cut -c -10240 | egrep 'katello_docker_meta_tags'"
			log "---"
			log

                        log "// ERROR count"
                        log "grep -h -i ERROR \$base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | wc -l"
                        log "---"
                        log_cmd "grep -h -i ERROR $base_dir/var/opt/rh/rh-postgresql12/lib/pgsql/data/log/*.log | wc -l"
                        log "---"
                        log

		fi


	  fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## mongodb (deprecated in 6.10)' | grep --color=always \#"
	  echo '## mongodb (deprecated in 6.10)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log


	   if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep mongod`" ] || [ ! "`egrep -i mongo $base_dir/chkconfig $base_dir/sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V $base_dir/sos_commands/process/ps_auxwww 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/etc/mongodb" ] && [ ! -d "$base_dir/var/log/mongodb" ]; then

		log "mongodb not found"
		log

	  else

	    log "MongoDB is a NoSQL database server which is used by Pulp to store the metadata related to the synchronized repositories and their contents. Pulp also uses MongoDB to store information about Pulp tasks and their current state.  MongoDB was deprecated in Satellite 6.10."
	    log


                #SERVICE_NAME='mongod'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all | egrep -v mongos"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='mongod'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log
                SERVICE_NAME='rh-mongodb34-mongod'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// is mongodb listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep '^Active|^Proto|mongod' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// mongodb memory consumption"
		log "from $base_dir/ps"
		log "---"
		log_cmd "grep -i mongo $base_dir/ps 2>&1 | sort -nr | awk '{print \$1, \$6}' | grep -v ^USER | grep -v ^COMMAND | grep -v \"^ $\" | awk  '{a[\$1] += \$2} END{for (i in a) print i, a[i]}' | sort -nrk2"
		log "---"
		log

		log "// cacheSize setting in custom hiera file"
		log "egrep 'mongodb::server::config_data|cacheSizeGB' \$base_dir/etc/foreman-installer/custom-hiera.yaml"
		log "---"
		log_cmd "egrep 'mongodb::server::config_data|cacheSizeGB' $base_dir/etc/foreman-installer/custom-hiera.yaml 2>&1"
		log "---"
		log


		log "// mongodb storage consumption"
		log "cat \$base_dir/sos_commands/foreman/foreman-debug/mongodb_disk_space"
		log "---"
		log_cmd "cat $base_dir/sos_commands/foreman/foreman-debug/mongodb_disk_space"
		log "---"
		log

		log "// hugepages tuning settings"
		log "---"
		log_cmd "grep hugepages $base_dir/etc/default/grub;if [ \"`grep hugepages $base_dir/etc/tuned/* 2>/dev/null`\"]; then echo; grep hugepages $base_dir/etc/tuned/* 2>/dev/null; echo active tuned profile; cat $base_dir/sos_commands/tuned/tuned-adm_active; fi"
		log "---"
		log

		log "// mongodb errors in messages file (last 50)"
		log "grep messages files for errors"
		log "---"
		#{ for mylog in `ls -rt $base_dir/var/log/messages* 2>/dev/null`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep -i ERROR | egrep "\{|\}" | egrep -v 'succeeded|dynflow-sidekiq|pulp_database.units_rpm|filebeat|goferd|pulp_database.consumer_unit_profiles|auditbeat' | uniq | tail -50 | cut -c -10240 >> $FOREMAN_REPORT
		log_cmd "egrep -i ERROR $base_dir/sysmgmt/messages.mongo | egrep mongod |  egrep -v 'succeeded|dynflow-sidekiq|pulp_database.units_rpm|filebeat|goferd|pulp_database.consumer_unit_profiles|auditbeat|command pulp_database' | uniq | tail -50 | cut -c -10240"
		log "---"
		log


	  fi



	  export GREP_COLORS='ms=01;32'
	  log_cmd "echo '## httpd (Apache)' | grep --color=always \#"
	  echo '## httpd (Apache)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
	  log


	   if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep httpd`" ] || [ ! "`egrep -i httpd $base_dir/chkconfig $base_dir/sos_commands/process/ps_auxwww 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/httpd" ]; then

		log "httpd not found"
		log

	  else


		log "The httpd.service is responsible for the REST API. It will create a pool of child processes or threads to handle requests.  Passenger and Pulp, which are core components of Satellite, depend upon Apache HTTP Server to serve incoming requests. Requests that arrive through the web UI or the Satellite API are received by Apache HTTP Server and then forwarded to the components of Satellite that operate on them."
		log

                log "// httpd packages"
                log "egrep 'httpd' $base_dir/sos_commands/yum/yum_list_installed"
                log "---"
                log_cmd "egrep 'httpd' $base_dir/sos_commands/yum/yum_list_installed"
                log "---"
                log


                #SERVICE_NAME='httpd'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* light\" -A 20 | sed -n \"/^\* light/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='httpd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log
                SERVICE_NAME='light-httpd'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            	log "// is apache listening?"
            	log "grepping netstat_-W_-neopa file for ports 443 and 80"
            	log "---"
            	log_cmd "egrep '^Active|^Proto|httpd' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
            	log "---"
            	log

		log "// queues on error_log means the # of requests crossed the border - satellite inaccessible"
		log "grep 'Request queue is full' \$base_foreman/var/log/httpd/error_log | wc -l"
		log "---"
		log_cmd "grep 'Request queue is full' $base_foreman/var/log/httpd/error_log | wc -l"
		log "---"
		log

		log "// when finding something on last step, we will list the date here"
		log "grep queue \$base_foreman/var/log/httpd/error_log  | awk '{print \$2, \$3}' | cut -d: -f1,2 | uniq -c"
		log "---"
		log_cmd "grep queue $base_foreman/var/log/httpd/error_log  | awk '{print \$2, \$3}' | cut -d: -f1,2 | uniq -c"
		log "---"
		log

                log "// sysctl configuration (older than 6.9)"
                log "cat \$base_dir/etc/01-satellite-tune.conf"
                log "---"
                log_cmd "cat $base_dir/etc/01-satellite-tune.conf"
		log "---"
		log
		log "  Note:  For PassengerMaxPoolSize > 256, please run these commands:"
		log
		log "    echo 'kernel.sem= 250 256000 32 16384' > /etc/sysctl.d/01-satellite-tune.conf"
		log "    echo 'fs.aio-max-nr = 1000000' >> /etc/sysctl.d/01-satellite-tune.conf"
		log
		log "    # sysctl -p /etc/sysctl.d/01-satellite-tune.conf"
		log

                log "// httpd|apache limits"
                log "cat \$base_dir/etc/systemd/system/httpd.service.d/limits.conf"
                log "---"
                log_cmd "cat $base_dir/etc/systemd/system/httpd.service.d/limits.conf"
		log
		log "---"
		log
		log "  Note:  The following values are recommended for Satellite servers older than 6.9:"
		log
		log "    [Service]"
		log "    LimitNOFILE=640000"
		log
		log "  Then run these commands:"
		log "    # systemctl daemon-reload"
		log "    # foreman-maintain service restart"
		log

                log "// prefork.conf configuration"
                log "egrep 'ServerLimit|StartServersMaxClients' \$base_dir/etc/httpd/conf.modules.d/prefork.conf"
                log "---"
                log_cmd "egrep 'ServerLimit|StartServers|MaxClients' $base_dir/etc/httpd/conf.modules.d/prefork.conf"
                log "---"
                log

          	log "// \'apache::purge_configs:\' setting in custom hiera"
          	log "egrep 'apache::purge_configs:' \$base_foreman/etc/foreman-installer/custom-hiera.yaml"
          	log "---"
          	log_cmd "egrep 'apache::purge_configs:' $base_foreman/etc/foreman-installer/custom-hiera.yaml"
          	log "---"
          	log
          	log "Note:  The setting \"apache::purge_configs: false\" is incompatible with Satellite 6.10 and above."
          	log

		#if [ -f "$base_foreman/var/log/httpd/foreman-ssl_access_ssl.log" ]; then
		if [ -f "$base_dir/sysmgmt/foreman-ssl_access_ssl.log" ]; then

                log "// TOP 20 IP addresses sending https requests to Satellite (Satellite and capsule servers highlighted)"
                #log "awk '{print \$1}' \$base_foreman/var/log/httpd/foreman-ssl_access_ssl.log | sort | uniq -c | sort -nr | head -n20"
                log "awk '{print \$1}' \$base_dir/sysmgmt/foreman-ssl_access_ssl.log | sort | uniq -c | sort -nr | head -n20"
                log "---"
                log_cmd "awk '{print \$1}' $base_dir/sysmgmt/foreman-ssl_access_ssl.log | sort | uniq -c | sort -nr | head -n20 | egrep --color=always \"^|$SATELLITE_IP|$CAPSULE_IPS\""
                log "---"
                log

		log "// TOP 20 IP addresses sending https requests to Satellite - not from Satellite or capsule servers (detailed)"
		log "awk '{print \$1,\$4}' \$base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep -v '\$SATELLITE_IP|\$CAPSULE_IPS' | cut -d: -f1,2,3 | uniq -c | sort -nr | head -n20"
		log "---"
		log_cmd "awk '{print \$1,\$4}' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep -v '$SATELLITE_IP|$CAPSULE_IPS' | cut -d: -f1,2,3 | uniq -c | sort -nr | head -n20 | egrep --color=always \"^|$CAPSULE_IPS\""
		log "---"
		log

		log "// TOP 50 URIs sending https requests to Satellite - not from Satellite or capsule servers"
		log "awk '{print \$1, \$6, \$7}' \$base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep -v '\$SATELLITE_IP|\$CAPSULE_IPS' | sort | uniq -c | sort -nr | head -n 50"
		log "---"
		log_cmd "awk '{print \$1, \$6, \$7}' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep -v '$SATELLITE_IP|$CAPSULE_IPS' | sort | uniq -c | sort -nr | head -n 50 | egrep --color=always \"^|$CAPSULE_IPS\""
		log "---"
		log

		#log "// TOP 50 URIs sending https requests to Satellite - from Satellite server"
		#log "awk '{print \$1, \$6, \$7}' \$base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep '\$SATELLITE_IP' | sort | uniq -c | sort -nr | head -n 50"
		#log "---"
		#log_cmd "awk '{print \$1, \$6, \$7}' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep '$SATELLITE_IP' | sort | uniq -c | sort -nr | head -n 50"
		#log "---"
		#log

                #log "// TOP 50 URIs sending https requests to Satellite - from capsule servers"
                #log "awk '{print \$1, \$6, \$7}' \$base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep '\$CAPSULE_IPS' | egrep -v '\$SATELLITE_IP' | sort | uniq -c | sort -nr | head -n 50"
                #log "---"
                #log_cmd "awk '{print \$1, \$6, \$7}' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | egrep '$CAPSULE_IPS' | egrep -v '$SATELLITE_IP' | sort | uniq -c | sort -nr | head -n 50"
                #log "---"
                #log

		log "// General HTTP return codes in apache logs"
		log "\$n;grep -P '\" \$n\d\d ' \$base_foreman/sysmgmt/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
		log "---"
		log_cmd "grep -P '\" 2\d\d ' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
		log
		log_cmd "grep -P '\" 3\d\d ' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
		log
		log_cmd "grep -P '\" 4\d\d ' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
		log
		log_cmd "grep -P '\" 5\d\d ' $base_foreman/sysmgmt/foreman-ssl_access_ssl.log | awk '{print \$9}' | sort | uniq -c | sort -nr"
		log "---"
		log
		log "2xx: success:  the request was successfully received, understood, and accepted"
		log "3xx: redirect:  further action needs to be taken in order to complete the request"
		log "4xx: client error:  the request contains bad syntax or cannot be fulfilled"
		log "5xx: server error:  the server failed to fulfil an apparently valid request"
		log "HTTP code reference:  https://en.wikipedia.org/wiki/List_of_HTTP_status_codes"
		log

		fi


	  fi


          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## puppet' | grep --color=always \#"
	  echo '## puppet' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log


	   if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep puppet`" ] || [ ! "`egrep puppet $base_dir/chkconfig $base_dir/sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V $base_dir/sos_commands/process/ps_auxwww 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/puppetlabs" ] && [ ! -d "$base_dir/var/log/puppet" ] && [ ! -d "$base_dir/etc/puppet" ] && [ ! -d "$base_dir/etc/puppetlabs" ]; then

		log "puppet not found"
		log

	  else

	    log "Puppet 3 is a Ruby application and runs inside the Passenger application server, whereas Puppet 4 runs as a standalone Java-based application. Puppet 3 came with Satellite 6.3, Puppet 4 and 5 came with Satellite 6.4, and Puppet 6 came with Satellite 6.8."
	    log

	    log "The Satellite server uses Puppet to manage its configuration files, and (prior to version 6.8) as its default software configuration tool for hosts.  Hosts also use Puppet to send facts to the Satellite server, although workarounds are available to do this without Puppet."
	    log


                log "// puppet packages"
                log "egrep '^puppet' $base_dir/sos_commands/yum/yum_list_installed"
                log "---"
                log_cmd "egrep '^puppet' $base_dir/sos_commands/yum/yum_list_installed | egrep -v '$HOSTNAME'"
                log "---"
                log


                #SERVICE_NAME='puppet'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='puppet'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            	log "// is puppet listening?"
            	log "grepping netstat_-W_-neopa file for port 8140"
            	log "---"
            	log_cmd "egrep '^Active|^Proto|\:8140' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
            	log "---"
            	log

                log "// check noexec property on tmp directories"
                log "egrep 'noexec|ro' \$base_dir/mount | grep \/tmp"
		log "egrep 'noexec|ro' \$base_dir/etc/fstab | grep \/tmp"
                log "---"
                log_cmd "egrep 'noexec|ro' $base_dir/mount,etc | grep \/tmp"
		log
		log_cmd "egrep 'noexec|ro' $base_dir/etc/fstab | grep \/tmp"
                log "---"
                log

          	log "Note:  Puppet and puppetserver can fail when /tmp and/or /var/tmp are mounted read-only, so look for that."
          	log

                log "// check for tmpdir in puppetserver and custom hiera files"
                log "egrep tmpdir \$base_dir/etc/sysconfig/puppetserver \$base_dir/etc/foreman-installer/custom-hiera.yaml"
                log "---"
                log_cmd "egrep tmpdir $base_dir/etc/sysconfig/puppetserver \$base_dir/etc/foreman-installer/custom-hiera.yaml"
                log "---"
                log

                log "// check puppet certificate dates"
                log "---"
                OUTPUT=$(MYDATE=`date -d "\`cat $base_dir/date\`" +"%Y%m%d%H%M"`;for i in $base_dir/var/lib/puppet/ssl/certs/ca.pem $base_dir/etc/puppetlabs/puppet/ssl/certs/ca.pem; do echo $i; START_DATE=`openssl x509 -in $i -noout -text | egrep -i "not before" | sed s'/Not Before://'g | sed 's/^[ \t]*//;s/[ \t]*$//'`; END_DATE=`openssl x509 -in $i -noout -text | egrep -i "not after" | sed s'/Not After ://'g | sed 's/^[ \t]*//;s/[ \t]*$//'`; echo -n 'Not Before: '; if [ "`date -d \"$START_DATE\" +\"%Y%m%d%H%M\"`" -gt "$MYDATE" ]; then echo "$START_DATE" | egrep . --color=always; else echo $START_DATE; fi; echo -n 'Not After : '; if [ "`date -d \"$END_DATE\" +\"%Y%m%d%H%M\"`" -lt "$MYDATE" ]; then echo "$END_DATE" | egrep . --color=always; else echo $END_DATE; fi; echo; done;)

                log "$OUTPUT"
                log "---"
                log

		log "// puppetserver memory allocation"
		log "grep 'JAVA_ARGS=' \$base_dir/etc/sysconfig/puppetserver"
		log "---"
		log_cmd "grep 'JAVA_ARGS=' $base_dir/etc/sysconfig/puppetserver"
		log "---"
		log
		log "Note: If too little memory is allocated to puppetserver, the puppetserver service can over-use the CPU."
		log

                log "// puppetserver memory usage"
                log "from \$base_dir/ps"
                log "---"
                if [ -f "$base_dir/ps" ] && [ "$(grep puppetserver $base_dir/ps)"  ]; then
                        num=0;
                        for i in `grep puppetserver $base_dir/ps | awk '{print $6}'`; do
                                num=`expr $num + $i`;
                        done;
                        num=`expr $num / 1024`
                        log "$num Mib";
                fi
                log "---"
                log


                log "// Puppet Server Error"
                log "egrep 'ERROR|Fail' \$base_dir/var/log/puppetlabs/puppetserver/puppetserver.log \$base_dir/var/log/puppet/puppetserver/puppetserver.log 2>/dev/null"
                log "---"
                log_cmd "egrep 'ERROR|Fail' $base_dir/var/log/puppetlabs/puppetserver/puppetserver.log $base_dir/var/log/puppet/puppetserver/puppetserver.log 2>/dev/null | tail -100"
                log "---"
                log

                log "// error: Setting puppetrun has no definition"
                log "---"
                log "count occurrences in /var/log/messages and /var/log/foreman/production.log"
                log_cmd "egrep -ir 'Setting puppetrun has no definition' $base_dir/sysmgmt/messages $base_dir/sysmgmt/production.log | wc -l"
                log
                log "count occurrences in the journal"
                log_cmd "egrep -ir 'Setting puppetrun has no definition' $base_dir/sysmgmt/journal.log | wc -l"
                log "---"
                log

                log "// foreman puppetserver mentions"
                log "egrep puppetserver \$base_dir/var/log/foreman-maintain/foreman-maintain.log 2>/dev/null | tail"
                log "---"
                log_cmd "egrep puppetserver $base_dir/sysmgmt/foreman-maintain.log 2>/dev/null | tail"
                log "---"
                log

	  fi


          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## pulp' | grep --color=always \#"
	  echo '## pulp' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep pulp`" ] || [ ! "`egrep -i 'pulp|pulpcore_client' $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

		log "pulp not found"
		log


	  else

	    log "Pulp, a component of Katello, is a software repository management tool written in Python. Pulp provides complete software repository management and the capability to mirror repositories, the capability to host repositories, and the capability to distribute the contents of those repositories to a large number of consumers."
	    log

	    log "Pulp manages RPM content, Puppet modules, and container images in Satellite. Pulp also publishes Content Views and creates local repositories from which Capsules and hosts retrieve content. The configuration of the Apache HTTP Server determines how efficiently Pulp REST API requests are handled."
	    log

	    log "Pulp depends upon Apache server to provide access to Pulp's APIs and internal components."
	    log

	    log "Pulp3, introduced in Satellite 6.10, stores on demand packages in postgres rather than as soft links on disk.  Pulp3's storage scheme is incompatible with both pulp2 and with pulp-admin."
	    log

	    log "The pulp_streamer is a streaming proxy service that translates the files in Pulp repositories to their locations in upstream repositories. This service interacts with Pulp’s core services to determine where the content is located and how to download it. It streams the content back to the client through Squid and Apache httpd as it is downloaded."
	    log

                log "Pulp celery resource_manager is responsible for dispatching Pulp jobs among worker threads.  When you see log messages about tasks that reserve and release resources, this is the worker that performs those tasks.  Only one of these services should be running at once.  In Satellite 6.10/pulp3, celery was removed, but resource_manager remains."
                log

	    log "The pulp_workers.service is responsible for downloading data from upstream repositories, and for publishing.  Pulp workers depend on celery."
	    log



                #SERVICE_NAME='pulp'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #OUTPUT=$(cat $base_dir/sysmgmt/services.txt | sed -n '/\.service -/,/\* /p' | egrep "^\* $SERVICE_NAME|^\● $SERVICE_NAME" $base_dir/sos_commands/systemd/systemctl_status_--all -A 1000 | sed -n "/$SERVICE_NAME/,/\* /p" | sed '$ d' | egrep -v "\||\`" | head -20 | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED')
                #log_cmd "echo -e \"$OUTPUT\""
                #log "---"
                #log

                SERVICE_NAME='pulp'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log


                log "// resource_manager status"
                log "from output of qpid-stat_-q_--ssl-certificate"
                log "---"
                log_cmd "egrep -h 'resource_manager|\=|bytesIn|AuthenticationFailure|ConnectionError' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | egrep -v '0     0      0       0      0        0'"
                log "---"
                log

                log "// premigration batch size (for 6.10 upgrades)"
                log "egrep PULP_CONTENT_PREMIGRATION_BATCH_SIZE \$base_dir/etc/systemd/system/pulpcore-worker@.service.d/settings.conf"
                log "---"
                log_cmd "egrep PULP_CONTENT_PREMIGRATION_BATCH_SIZE $base_dir/etc/systemd/system/pulpcore-worker@.service.d/settings.conf"
                log "---"
                log

                log "// pulp worker timeout"
                log "egrep ^worker_timeout \$base_dir/etc/pulp/server.conf"
                log "---"
                log_cmd "egrep ^worker_timeout $base_dir/etc/pulp/server.conf"
                log "---"
                log


		log "// pulp_workers configuration"
		log "egrep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY|pulpcore_worker_count' \$base_dir/etc/default/pulp_workers \$base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}"
		log "---"
		log_cmd "egrep '^PULP_MAX_TASKS_PER_CHILD\|^PULP_CONCURRENCY|pulpcore_worker_count' $base_dir/etc/default/pulp_workers $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}"
		log "---"
		log

          	log "// number of CPUs"
          	log "grep processor \$base_dir/proc/cpuinfo | wc -l"
          	log "---"
          	log_cmd "if [ -f $base_dir/sos_commands/processor/lscpu ]; then egrep '^CPU\(s\):' $base_dir/sos_commands/processor/lscpu; elif [ -f $base_dir/proc/cpuinfo ]; then grep processor $base_dir/proc/cpuinfo | wc -l; elif [ -f $base_dir/procs ]; then cat $base_dir/procs; fi"
          	log "---"
          	log

            	log "// pulp squid port"
            	log "egrep pulp -A 1 \$base_dir/etc/squid/squid.conf"
            	log "---"
          	export GREP_COLORS='ms=01;33'
            	log_cmd "egrep pulp -A 1 $base_dir/etc/squid/squid.conf | egrep '^$|http_port|3128|accel|defaultsite=|127.0.0.1|\:8751' --color=ALWAYS"
		export GREP_COLORS='ms=01;31'
            	log "---"
            	log

		if [ "egrep -v ConnectionError $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate"  ]; then
		log "// Total number of configured pulp agents"
		log "grep -h pulp.agent \$base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | wc -l"
		log "---"
		log_cmd "grep -h pulp.agent $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | wc -l"
		log "---"
		log

		log "// Total number of (active) pulp agents"
		log "egrep -h 'pulp.agent|Anonymous connections disabled|AuthenticationFailure' \$base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | grep \" 1.*1\$\" | wc -l"
		log "---"
		log_cmd "egrep -h 'pulp.agent|Anonymous connections disabled|AuthenticationFailure' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | grep \" 1.*1\$\" | wc -l"
		log "---"
		log
		else

                log "// output of qpid-stat_-q command"
                log "cat \$base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate"
                log "---"
		log_cmd "cat $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate"
                log "---"
                log

		fi

		log "// unfinished pulp tasks"
		log "grep -E '(\"finish_time\" : null|\"start_time\"|\"state\"|\"pulp:|^})' \$base_dir/sos_commands/pulp/pulp-running_tasks"
		log "---"
		log_cmd "grep '\"task_id\"' $base_dir/sos_commands/pulp/pulp-running_tasks | wc -l"
		log "---"
		log
		log_cmd "grep -E '(\"finish_time\" : null|\"start_time\"|\"state\"|\"pulp:|^})' $base_dir/sos_commands/pulp/pulp-running_tasks | uniq"
		log "---"
		log

                log "// migration errors"
                log "egrep pulp_2to3_migration \$base_dir/sos_commands/foreman/foreman-maintain_service_status"
                log "---"
                log_cmd "egrep pulp_2to3_migration $base_dir/sos_commands/foreman/foreman-maintain_service_status | tail -100"
                log "---"
                log

	  fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## redis' | grep --color=always \#"
          echo '## redis' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep redis`" ] || [ ! "`egrep -i redis $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

                log "redis not found"
                log


          else

            log "Redis was added to Satellite version 6.7."
            log

            log "Redis is an open source (BSD licensed), in-memory data structure store used as a database, cache, message broker, and streaming engine. Redis provides data structures such as strings, hashes, lists, sets, sorted sets with range queries, bitmaps, hyperloglogs, geospatial indexes, and streams. Redis has built-in replication, Lua scripting, LRU eviction, transactions, and different levels of on-disk persistence, and provides high availability via Redis Sentinel and automatic partitioning with Redis Cluster."
            log


            #    SERVICE_NAME='redis'
            #    log "// $SERVICE_NAME service status"
            #    log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
            #    log "---"
            #    log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v sentinel | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
            #    log
            #    if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
            #    log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
            #    log "---"
            #    log

                SERVICE_NAME='redis'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket|\-sentinel' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                SERVICE_NAME='rh-redis5-redis'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log


            log "// is redis listening?"
            log "grepping netstat_-W_-neopa file"
            log "---"
            log_cmd "egrep '^Active|^Proto|redis' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
            log "---"
            log


	    log "redis logs:"
            log "---"
	    log_cmd "egrep -hir 'No space left on device$' $base_dir/var/log/redis | sort -k4h -k3M -k2h -k5 | tail -10"
            log "---"
	    log

          fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## celery (deprecated in 6.10)' | grep --color=always \#"
          echo '## celery (deprecated in 6.10)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep celery`" ] || [ ! "`egrep -i celery $base_dir/installed_rpms 2>/dev/null | head -1`" ] && [ ! "`egrep -i celerybeat $base_dir/chkconfig 2>/dev/null | head -1`" ]; then

                log "celery not found"
                log
                log "Note: In Satellite 6.10, celery was removed, but resource_manager remains."
                log

          else

                log "Pulp celery resource_manager is responsible for dispatching Pulp jobs among worker threads.  When you see log messages about tasks that reserve and release resources, this is the worker that performs those tasks.  Only one of these services should be running at once.  In Satellite 6.10, celery was removed, but resource_manager remains."
                log

                #SERVICE_NAME='celery'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='celerybeat'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// resource_manager status"
                log "from output of qpid-stat_-q command"
                log "---"
                log_cmd "egrep -h 'resource_manager|celery|\=|bytesIn' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | egrep -v '0     0      0       0      0        0'"
                log "---"
                log

                log "// active celery workers (pre-6.10)"
                log "egrep celery \$base_dir/ps"
                log "---"
                log_cmd "egrep celery $base_dir/ps"
                log "---"
                log

                log "// celery errors"
                log "egrep celery \$base_dir/var/log/messages | egrep ERROR"
                log "---"
                log_cmd "egrep celery $base_dir/sysmgmt/messages | egrep ERROR | tail -100"
                log "---"
                log

           fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## squid (deprecated in 6.10)' | grep --color=always \#"
	  echo '## squid (deprecated in 6.10)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep squid`" ] || [ ! "`egrep -i squid $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

                log "squid not found"
                log

          else

            log "Squid is a caching and forwarding HTTP web proxy supporting http, https, FTP and more. The squid service is used by pulp as is a core component of Red Hat Satellite 6.  When 1 or more clients request a package with yum install $package, it gets downloaded to the squid proxy cache and every 10 minutes, a process runs which copies downloaded packages from the squid cache to disk.  The squid service also supports Satellite's various download policies for repository and capsule syncs."
            log

	    log "Note: Squid was removed in Satellite 6.10."
	    log


                #SERVICE_NAME='squid'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='squid'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// is squid listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep '^Active|^Proto|squid' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

            log "// pulp squid port"
            log "egrep pulp -A 1 \$base_dir/etc/squid/squid.conf"
            log "---"
            export GREP_COLORS='ms=01;33'
            log_cmd "egrep pulp -A 1 $base_dir/etc/squid/squid.conf | egrep '^$|http_port|3128|accel|defaultsite=|127.0.0.1|\:8751' --color=ALWAYS"
            export GREP_COLORS='ms=01;31'
            log "---"
            log

            log "// squid log errors"
            log "tail -50 \$base_dir/var/log/squid/cache.log"
            log "---"
	    log_cmd "tail -50 $base_dir/var/log/squid/cache.log"
            log "---"
            log

          fi



          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## qpidd (deprecated in 6.10)' | grep --color=always \#"
	  echo '## qpidd (deprecated in 6.10)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep qpidd`" ] || [ ! "`egrep -i 'qpidd' $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps $base_dir/sos_commands/qpid/ls_-lanR_.var.lib.qpidd $base_dir/etc/qpid/qpidd.conf 2>/dev/null | head -1`" ]; then

		log "qpidd not found"
		log

                log "Note:  qpidd was deprecated on Satellite 6.10.  To install it, please run this command:"
                log '    # satellite-installer --foreman-proxy-content-enable-katello-agent true'
                log

	  else

		log "Apache Qpid is a cross-platform Enterprise Messaging system that implements the Advanced Messaging Queue Protocol (AMQP)."
		log

		log "AMQP Messaging uses a Producer - Consumer model. Communication between the message producers and message consumers is decoupled by a broker that provides exchanges and queues. This allows applications to produce and consume data at different rates. Producers send messages to exchanges on the message broker. Consumers subscribe to exchanges that contain messages of interest, creating subscription queues that buffer messages for the consumer. Message producers can also create subscription queues and publish them for consuming applications."
		log

		log "The messaging broker functions as a decoupling layer, providing exchanges that distribute messages, the ability for consumers and producers to create public and private queues and subscribe them to exchanges, and buffering messages that are sent at-will by producer applications, and delivered on-demand to interested consumers."
		log

		log "Note:  In Satellite 6.10, qpidd was deprecated on capsule servers."
		log




                #SERVICE_NAME='qpidd'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='qpidd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

		if [ "`grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data 2>/dev/null | grep qpid`" ]; then
			log "// 3rd party qpidd packages"
			log "from file $base_dir/sos_commands/rpm/package-data"
			log "---"
			log_cmd "grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | grep qpid | egrep -v None$ | grep -v ^$HOSTNAME | cut -f1,4 | sort -k2"
			log "---"
			log
		fi

                log "// is qpidd listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep '^Active|^Proto|qpidd' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// qpidd disk usage"
		log "grep \"^-\" \$base_dir/sos_commands/qpid/ls_-lanR_.var.lib.qpidd 2>/dev/null | awk '{ s+=\$5 } END {printf \"\%d\", s}' | numfmt --to=iec"
		log "---"
		QPIDD_DISK_USAGE=`grep "^-" $base_dir/sos_commands/qpid/ls_-lanR_.var.lib.qpidd 2>/dev/null | awk '{ s+=$5 } END {printf "%d", s}' | numfmt --to=iec`
		log "$QPIDD_DISK_USAGE"
		log "---"
		log

		log "// qpidd configuration"
		log "grep mgmt_pub_interval \$base_dir/etc/qpid/qpidd.conf"
		log "---"
		log_cmd "grep mgmt_pub_interval $base_dir/etc/qpid/qpidd.conf"
		log "---"
		log

		log "// qpidd limits"
		log "grep LimitNOFILE \$base_dir/etc/systemd/system/qpidd.service.d/90-limits.conf"
		log "---"
		log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/qpidd.service.d/90-limits.conf"
		log "---"
		log

	  fi

          export GREP_COLORS='ms=01;32'
          log_cmd "echo '## qdrouterd (deprecated in 6.10)' | grep --color=always \#"
	  echo '## qdrouterd (deprecated in 6.10)' | grep --color=always \#
          export GREP_COLORS='ms=01;31'
          log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep qdrouterd`" ] || [ ! "`egrep -i 'qdrouterd' $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

		log "qdrouterd not found"
		log

	  else


		log "The qdrouterd.service is a network daemon that directs messages between endpoints, such as messaging clients and servers.  Unlike message brokers, they do not take responsibility for messages.  The (AMQP) router network will deliver the message, possibly through several intermediate routers – and then route the consumer’s acknowledgement of that message back across the same path."
		log
		log "The qdrouterd service communicates with goferd, which is expected to run on the host servers (including capsule servers)."
                log
                log "Note:  qdrouterd was deprecated in Satellite 6.10.  To install it, please run this command:"
                log '    # satellite-installer --foreman-proxy-content-enable-katello-agent true'
		log


                #SERVICE_NAME='qdrouterd'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='qdrouterd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// is qdrouterd listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep '^Active|^Proto|qdrouterd' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// qrouterd limits"
		log "grep LimitNOFILE \$base_dir/etc/systemd/system/qdrouterd.service.d/90-limits.conf"
		log "---"
		log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/qdrouterd.service.d/90-limits.conf"
		log "---"
		log

	  fi


	  log_tee "## passenger (deprecated in 6.9)"
	  log

                log "// are any passenger gems installed?"
                log "grep passenger \$base_dir/sos_commands/ruby/gem_list"
                log "---"
                log_cmd "grep passenger $base_dir/sos_commands/ruby/gem_list"
                log "---"
                log

	  if [ ! "`egrep . $base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf $base_dir/etc/httpd/conf.d/passenger.conf 2>/dev/null | head -1`" ] && [ ! "`egrep -i general $base_dir/sos_commands/foreman/passenger-status_--show_pool 2>/dev/null | head -1`" ]; then

		log "passenger not found"
		log

	  else

	    log "Passenger is a web server and a core component of Red Hat Satellite. Satellite uses Passenger to run Ruby applications such as Foreman and Puppet. Passenger integrates with Apache HTTP Server to capture incoming requests and redirects them to the respective components that handle them."
	    log

	    log "Passenger is involved in Satellite when the GUI is accessed, when the APIs are accessed, and when content hosts are registered. Each request that is serviced by Passenger consumes an Apache HTTP Server process. Passenger queues requests into an application-specific wait queue. The maximum number of requests that can be queued by Passenger is defined in the Passenger configuration. When running at scale, it might be desirable to increase the number of requests that Passenger can handle concurrently. It might also be desirable to increase the size of the wait queue to accommodate bursts of requests."
	    log

	    log "Passenger is configured within the Apache HTTP Server configuration files. It can be used to control the performance, scaling, and behavior of Foreman and Puppet."
	    log

                log "// is passenger listening?"
                log "grepping netstat_-W_-neopa file"
                log "---"
                log_cmd "egrep -i '^Active|^Proto|passenger' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// 3rd party passenger packages"
		log "from file $base_dir/sos_commands/rpm/package-data"
		log "---"
		log_cmd "grep -v 'Red Hat' $base_dir/sos_commands/rpm/package-data | grep passenger | cut -f1,4 | sort -k2"
		log "---"
		log

                log "// passenger pool status"
                log "egrep -A 3 'General information' \$base_dir/sos_commands/foreman/passenger-status_--show_pool"
                log "---"
                log_cmd "egrep -A 3 'General information' $base_dir/sos_commands/foreman/passenger-status_--show_pool"
                log "---"
                log

		log "// passenger memory usage"
		log "egrep 'Passenger processes' -A 100 \$base_dir/sos_commands/foreman/passenger-memory-stats"
		log "---"
		log_cmd "egrep 'Passenger processes' -A 100 $base_dir/sos_commands/foreman/passenger-memory-stats 2>&1"
		log "---"
		log

		if [ -f "$base_dir/sos_commands/foreman/foreman_tasks_tasks" ]; then
		log "// total # of foreman tasks"
		log "cat \$base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
		log "---"
		log_cmd "cat $base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
		log "---"
		log
		fi

		log "// max_pool_size in custom hiera"
		log "grep passenger_max_pool_size \$base_dir/etc/foreman-installer/custom-hiera.yaml"
		log "---"
		log_cmd "grep passenger_max_pool_size $base_dir/etc/foreman-installer/custom-hiera.yaml 2>&1"
		log "---"
		log

		log "// passenger.conf configuration - 6.3 or earlier"
		log "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' \$base_dir/etc/httpd/conf.d/passenger.conf"
		log "---"
		log_cmd "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.d/passenger.conf 2>&1"
		log "---"
		log

		log "// passenger-extra.conf configuration - 6.4+"
		log "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' \$base_dir/etc/httpd/conf.modules.d/passenger_extra.conf"
		log "---"
		log_cmd "grep 'MaxPoolSize\|PassengerMaxRequestQueueSize' $base_dir/etc/httpd/conf.modules.d/passenger_extra.conf 2>&1"
		log "---"
		log

		log "// 05-foreman.conf configuration"
		log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' \$base_dir/etc/httpd/conf.d/05-foreman.conf"
		log "---"
		log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman.conf 2>&1"
		log "---"
		log

		log "// 05-foreman-ssl.conf configuration"
		log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' \$base_dir/etc/httpd/conf.d/05-foreman-ssl.conf"
		log "---"
		log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout\|PassengerMinInstances' $base_dir/etc/httpd/conf.d/05-foreman-ssl.conf 2>&1"
		log "---"
		log

		log "// URI requests"
		log "grep uri \$base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests | sort -k3 | uniq -c"
		log "---"
		log_cmd "grep uri $base_dir/sos_commands/foreman/sos_commands/foreman/passenger-status_--show_requests 2>&1 | sort -k3 | uniq -c"
		log "---"
		log

	  fi

	  log_tee "## puma (starting in 6.9)"
	  log

	  if [ ! "`egrep -i puma $base_dir/ps $base_dir/systemd/system/foreman.service.d/installer.conf $base_dir/installed-rpms 2>/dev/null | head -1`" ]; then

		log "puma not found"
		log

	  elif [ "`egrep -i 'satellite-6.7|satellite-6.8' $base_dir/installed-rpms 2>/dev/null | head -1`"  ]; then

	    log "Puma packages weren't used until Satellite 6.9, when it became a drop-in replacement for Passenger."
	    log

	    log "// installed puma packages"
	    log "grep puma \$base_dir/installed-rpms"
	    log "---"
	    log_cmd "grep puma $base_dir/installed-rpms 2>&1"
	    log "---"
	    log

	  else

	    log "Puma is a drop-in replacement for Passenger, and was introduced in Satellite 6.9.  It's a web server and a core component of Red Hat Satellite. Satellite uses Puma to run Ruby applications such as Foreman. Puma integrates with Apache HTTP Server to capture incoming requests and redirects them to the respective components that handle them."
	    log

	    log "Puma is involved in Satellite when the GUI is accessed, when the APIs are accessed, and when content hosts are registered. Each request that is serviced by Puma consumes an Apache HTTP Server process. Puma queues requests into an application-specific wait queue. The maximum number of requests that can be queued by Puma is defined in the Foreman service configuration. When running at scale, it might be desirable to increase the number of requests that Puma can handle concurrently. It might also be desirable to increase the size of the wait queue to accommodate bursts of requests."
	    log

	    log "// installed puma packages"
	    log "grep puma \$base_dir/installed-rpms"
	    log "---"
	    log_cmd "grep puma $base_dir/installed-rpms 2>&1"
	    log "---"
	    log

            log "// puma status"
            log "from file systemctl_status_--all"
            log "---"
            log_cmd "egrep 'foreman\.service -|Status:' $base_dir/sos_commands/systemd/systemctl_status_--all | egrep -A 1 'foreman\.service -' | grep Status:"
            log "---"
            log

	    log "// running puma processes"
	    log "grep puma \$base_dir/ps"
	    log "---"
	    log_cmd "grep puma $base_dir/ps 2>&1"
	    log "---"
	    log

	    log "// total # of foreman tasks"
	    log "cat \$base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
	    log "---"
	    log_cmd "cat $base_dir/sos_commands/foreman/foreman_tasks_tasks | wc -l"
	    log "---"
	    log

	    log "// puma performance settings"
	    log "grep -i puma \$base_dir/etc/systemd/system/foreman.service.d/installer.conf"
	    log "---"
	    log_cmd "grep -i puma $base_dir/etc/systemd/system/foreman.service.d/installer.conf"
	    log "---"
	    log

	  fi



	  log_tee "## foreman"
	  log


          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep foreman`" ] || [ ! "`egrep -i foreman $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps $base_dir/sysmgmt/production.log 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/foreman-proxy" ] && [ ! -d "$base_dir/var/log/foreman" ] && [ ! -d "$base_dir/var/log/foreman-installer" ] && [ ! -d "$base_dir/var/log/foreman-maintain" ] && [ ! -d "$base_dir/var/log/katello-installer" ]; then

		log "foreman not found"
		log

	  else

	    log "Foreman is a Ruby application that runs inside the Passenger application server and does a number of things, among them providing a UI, providing remote execution, running Foreman SCAP scans on content hosts. Foreman is also involved in Content Host Registrations.  Foreman’s performance and scalability are affected directly by the configurations of httpd and Passenger."
	    log
	    log "The foreman-proxy.service  manages the foreman-proxy. Foreman-Proxy is located on or near a machine that performs a specific function and helps foreman orchestrate the process of commissioning a new host. Placing the proxy on or near to the actual service will also help reduce latencies in large distributed organizations."
	    log



                #SERVICE_NAME='foreman'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v socket | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='foreman'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log


                log "// postgres idle processes (foreman)"
                log "grep ^postgres \$base_dir/ps | grep idle$ | grep \"foreman foreman\" | wc -l"
                log "---"
                log_cmd "grep ^postgres $base_dir/ps 2>&1 | grep idle$ | grep \"foreman foreman\" | wc -l"
                log "---"
                log

		# exclude satellite-specific entries on capsule servers
		if [ -f "$base_dir/etc/cron.d/foreman-tasks" ] || [ -f "$base_foreman/etc/foreman/settings.yaml" ] || [ -d "$base_foreman/var/log/foreman" ]; then


		log "// foreman tasks cleanup script"
		log "cat \$base_dir/etc/cron.d/foreman-tasks"
		log "---"
		log_cmd "cat $base_dir/etc/cron.d/foreman-tasks"
		log "---"
		log


		log "// foreman settings"
		log "cat \$base_foreman/etc/foreman/settings.yaml"
		log "---"
		log_cmd "cat $base_foreman/etc/foreman/settings.yaml | egrep --color=always '^|journald'"
		log "---"
		log

                log "// Tasks TOP"
                log "from file \$base_dir/sos_commands/foreman/foreman_tasks_tasks"
                log "---"
                #log_cmd "grep Actions $base_dir/sos_commands/foreman/foreman_tasks_tasks  | cut -d, -f3 | sed 's/^[ \t]*//;s/[ \t]*$//' | sort -k 7 | tail -100 | egrep --color=always '^|paused|running|error|pending|warning|scheduled' | sed s'/  //'g"
		tasks_top=`grep Actions $base_dir/sos_commands/foreman/foreman_tasks_tasks | sort -t "|" -k 10 | head -50 | awk -F"|" '{print $1, "|", $4, "|", $6, "|", $7, "|", $12}' | sed 's/^[ \t]*//;s/[ \t]*$//' | egrep --color=always '^|error|warning'`
		log "$tasks_top"
                log "---"
                log


                log "// paused foreman tasks"
                log "grepping foreman_tasks_tasks for paused tasks"
                log "---"
                log_cmd "grep -E '(^                  id|paused)' $base_dir/sos_commands/foreman/foreman_tasks_tasks | sed 's/  //g' | sed -e 's/ |/|/g' | sed -e 's/| /|/g' | sed -e 's/^ //g' | sed -e 's/|/,/g' | sort -t ',' -k 3"
                log "---"
                log

                log "// Failed Tasks TOP"
                log "from file \$base_dir/sos_commands/foreman/foreman_tasks_tasks"
                log "---"
                failed_tasks_top=`grep Actions $base_dir/sos_commands/foreman/foreman_tasks_tasks | egrep -v "success|running|scheduled" | sort -t "|" -k 10 | head -50 | awk -F"|" '{print $1, "|", $4, "|", $6, "|", $7, "|", $12}' | sed 's/^[ \t]*//;s/[ \t]*$//'`
                log "$failed_tasks_top"
                log "---"
                log

                log "// dynflow log errors"
                log "from directory \$base_dir/var/log/foreman/"
                log "---"
		#DYNFLOW_OUTPUT=$(for i in `find $base_dir/var/log/foreman/ -type f | egrep dynflow | egrep -v gz$`; do egrep -Hi 'except|error|fail' $i | sed s'/\\n/\n/'g | egrep -i "except|error|fail|$i" -A 3 -B 3; zgrep -Hie 'except|error|fail' $i | sed s'/\\n/\n/'g | egrep -i "except|error|fail|$i" -A 3 -B 3; done | tail -100)
		#DYNFLOW_OUTPUT=$(for i in `egrep 'warning|error' sosreport-*/sos_commands/foreman/foreman_tasks_tasks | awk '{print $1}'`; do egrep $i sosreport-*/var/log/foreman/dynflow*; zgrep $i sosreport-*/var/log/foreman/dynflow*; done)
                #log_cmd "echo -e \"$DYNFLOW_OUTPUT\""
	 	
		MYUUIDS=`egrep 'warning|error' $base_dir/sos_commands/foreman/foreman_tasks_tasks | awk '{print $1}' | tail -1000 | sort -u | tr '\n' '|' | rev | cut -c2- | rev`
		MYFILELIST=`find -L $base_dir/var/log/foreman -type f -maxdepth 1 | egrep dynflow`
		DYNFLOW_OUTPUT=$(if [ "$MYFILELIST" ]; then for i in "$MYFILELIST"; do zgrep . $i | egrep "$MYUUIDS" | tail -100; done | sort; fi)
		log_cmd "echo -e \"$DYNFLOW_OUTPUT\""
                log "---"
                log

		log "// total number of errors found on production.log - TOP 40"
		log "grep -h \"\[E\" \$base_foreman/var/log/foreman/production.log* | awk '{print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$13}' | sort | uniq -c | sort -nr | head -n40"
		log "---"
		log_cmd "grep -h \"\[E\" $base_dir/sysmgmt/production.log | awk '{print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$13}' | sort | uniq -c | sort -nr | head -n40"
		log "---"
		log

		fi

	  fi



	  log_tee "## dynflow"
	  log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep dynflow`" ] || [ ! "`egrep -i dynflow $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps $base_dir/sos_commands/foreman/foreman_tasks_tasks 2>/dev/null | head -1`" ] && [ ! -f "$base_dir/etc/sysconfig/dynflowd" ] && [ ! -f $base_dir/etc/foreman/dynflow/worker.yml ]; then

		log "dynflow not found"
		log

	  else

		log "DynFlow is a workflow system and task orchestration engine written in Ruby, and runs as a plugin to Foreman.  Foreman uses the dynflowd.service to keep track of the progress of running process. It run the code asynchronously, resumes the process when something goes wrong, skip some steps when needed, detects independent parts and runs them concurrently."
		log
		log "The smart_proxy_dynflow_core.service is a proxy service for dynflow.  This service was deprecated in Satellite 6.10."
		log

                #SERVICE_NAME='dynflow'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='dynflow'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                SERVICE_NAME='smart_proxy_dynflow_core'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

		log "// smart proxy dynflow core limits"
		log "grep LimitNOFILE \$base_dir/etc/systemd/system/smart_proxy_dynflow_core.service.d/90-limits.conf"
		log "---"
		log_cmd "grep LimitNOFILE $base_dir/etc/systemd/system/smart_proxy_dynflow_core.service.d/90-limits.conf"
		log "---"
		log

                log "// 6.3 or lower"
                log

		if [ -f "$base_dir/etc/sysconfig/foreman-tasks" ]; then

		log "// dynflow optimizations (only used before 6.8)"
		log "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" \$base_dir/etc/sysconfig/foreman-tasks"
		log "---"
		log_cmd "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/foreman-tasks"
		log
		log "Note:  For Satellite servers older than 6.8, EXECUTORS_COUNT=2 is recommended for 32 Gb of RAM, and EXECUTORS_COUNT=3 is recommended for 65+ Gb of RAM."
		log
		log "---"
		log

                log "// number of running dynflow executors (pre-6.8)"
                log "grep dynflow_executor\$ \$base_dir/ps"
                log "---"
                log_cmd "grep dynflow_executor\$ $base_dir/ps 2>&1"
                log "---"
                log

		log "// foreman-tasks/dynflow configuration"
		log "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' \$base_dir/etc/sysconfig/foreman-tasks"
		log "---"
		log_cmd "grep 'EXECUTOR_MEMORY_LIMIT\|EXECUTOR_MEMORY_MONITOR_DELAY\|EXECUTOR_MEMORY_MONITOR_INTERVAL' $base_dir/etc/sysconfig/foreman-tasks"
		log "---"
		log

                log "Notes:"
                log "    EXECUTOR_MEMORY_LIMIT defines the amount of memory that a single dynFlow executor process can consume before the executor is recycled."
                log
                log "    EXECUTOR_MEMORY_MONITOR_DELAY defines when the first polling attempt to check the executor memory is made after the initialization of the executor."
                log
                log "    EXECUTOR_MEMORY_MONITOR_INTERVAL defines how frequently the memory usage of executor is polled."
                log

		else

			log "didn't find config file sos_report/etc/sysconfig/foreman-tasks for 6.3 and below."
			log

		fi

                log "// 6.4 through 6.7"
                log

		if [ -f "$base_dir/etc/sysconfig/dynflowd" ]; then

                log "// dynflow optimizations (only used before 6.8)"
                log "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" \$base_dir/etc/sysconfig/foreman-tasks"
                log "---"
                log_cmd "egrep \"EXECUTORS_COUNT|MALLOC_ARENA_MAX\" $base_dir/etc/sysconfig/foreman-tasks"
                log
                log "Note:  For Satellite servers older than 6.8, EXECUTORS_COUNT=2 is recommended for 32 Gb of RAM, and EXECUTORS_COUNT=3 is recommended for 65+ Gb of RAM."
                log
                log "---"
                log

                log "// number of running dynflow executors (pre-6.8)"
                log "grep dynflow_executor\$ \$base_dir/ps"
                log "---"
                log_cmd "grep dynflow_executor\$ $base_dir/ps 2>&1"
                log "---"
                log

		log "// foreman-tasks/dynflow configuration"
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

		else

			log "6.4-6.7 config file sos_report/etc/sysconfig/dynflowd not found"
			log

		fi

                log "// 6.8 or higher"
                log

		if [ -d "$base_dir/etc/foreman/dynflow" ]; then

                log "// number of dynflow workers"
                log "list workers in \$base_dir/etc/foreman/dynflow/"
                log "---"
                log_cmd "echo `ls $base_dir/etc/foreman/dynflow/worker* | grep -v hosts | wc -l` workers"
                log_cmd "find $base_dir/etc/foreman/dynflow/ -type f | grep worker | grep -v hosts"
                log "---"
                log

		log "// dynflow configuration"
		log "cat \$base_dir/etc/foreman/dynflow/worker.yml"
		log "cat \$base_dir/etc/foreman/dynflow/worker-hosts-queue.yml"
		log "---"
		log_cmd "cat $base_dir/etc/foreman/dynflow/worker.yml"
		log
		log_cmd "cat $base_dir/etc/foreman/dynflow/worker-hosts-queue.yml"
		log "---"
		log

		else

			log "6.8+ directory sos_report/etc/foreman/dynflow not found"
			log
		fi


	  fi








	  log_tee "## tomcat"
	  log

	  if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep tomcat`" ] || [ ! "`egrep -i 'tomcat' $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -d "$base_dir/var/log/tomcat" ] && [ ! -d "$base_dir/var/log/tomcat6" ]; then

		log "tomcat not found"
		log

	  else

	    log "Apache Tomcat is an open-source, Java-based application development platform.  The tomcat.service renders pages written in JSP (Java Server Pages)."
	    log

                log "// tomcat packages"
                log "egrep -h tomcat \$base_dir/sos_commands/yum/yum_list_installed \$base_dir/installed_rpms"
                log "---"
                log_cmd "egrep -h tomcat $base_dir/sos_commands/yum/yum_list_installed $base_dir/installed_rpms"
                log "---"
                log




                #SERVICE_NAME='tomcat'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='tomcat'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

		log "// Memory (Xms and Xmx)"
		log "grep tomcat \$base_dir/ps"
		log "---"
		log_cmd "grep tomcat $base_dir/ps 2>&1"
		log
		tomcat_mem=`grep tomcat $base_dir/ps 2>&1 | awk '{print $6}'`
		if [ "$tomcat_mem" ]; then tomcat_mem_mb=`echo current memory consumption: $(($tomcat_mem / 1024 )) Mb 2>/dev/null`; else tomcat_mem_mb=''; fi
		log "$tomcat_mem_mb"
		log_cmd "echo java heap memory maximum: `grep tomcat $base_dir/ps 2>&1 | tr ' ' '\n' | grep Xmx`"


		if [ -e $base_dir/etc/tomcat6/tomcat.conf ]; then

                log
                log "grep 'JAVA_OPTS' \$base_dir/etc/tomcat6/tomcat6.conf"
                log
                log_cmd "grep 'JAVA_OPTS' $base_dir/etc/tomcat6/tomcat6.conf"
                log "---"
                log

		else

		log
		log "grep 'JAVA_OPTS' \$base_dir/etc/tomcat/tomcat.conf"
		log
		log_cmd "grep 'JAVA_OPTS' $base_dir/etc/tomcat/tomcat.conf"
		log "---"
		log

		fi

		if [ -e $base_dir/var/log/tomcat6 ]; then

                	log
                	log "tail -100 \$base_dir/var/log/tomcat6/catalina.log"
                	log
                	log_cmd "tail -100 $base_dir/var/log/tomcat6/catalina.log"
                	log "---"
                	log

		fi

	  fi


	  log_tee "## candlepin"
	  log

	  if [ ! "`egrep -i candlepin \"$base_dir/sos_commands/foreman/hammer_ping\" \"$base_dir/installed_rpms\" \"$base_dir/ps\" 2>/dev/null | head -1`" ] && [ ! -d $base_dir/sos_commands/candlepin ]; then

		log "candlepin not found"
		log

	  else

	    log "Candlepin is a collection of tools that facilitates the management of software subscriptions.  Candlepin runs on Tomcat, and is written in JSP (Java Server Pages). It is a part of Katello, which provides a unified workflow and web-based user interface for content and subscriptions."
	    log

		log "// hammer ping output"
		log "grep -A2 candlepin \$base_dir/sos_commands/foreman/hammer_ping"
		log "---"
		log_cmd "grep -A2 candlepin $base_dir/sos_commands/foreman/hammer_ping | egrep --color=always '^|FAIL'"
		log "---"
		log

                log "// is candlepin listening?"
                log "egrep file netstat_-W_-neopa for subscription-manager port 8443"
                log "---"
		log_cmd "egrep '^Active|^Proto|\:8443' $base_dir/sos_commands/networking/netstat_-W_-neopa | sed -n '/^Active/,/^Active/p' | sed '$ d' | egrep '^Active|^Proto|LISTEN'"
                log "---"
                log

		log "// latest state of candlepin (updating info)"
		log "grep -B1 Updated \$base_foreman/var/log/candlepin/candlepin.log"
		log "---"
		log_cmd "grep -B1 Updated $base_foreman/var/log/candlepin/candlepin.log | tail -100"
		log "---"
		log

                log "// verify whether simple content access (SCA) is enabled for hosts"
                #log "egrep -m 5 'org_environment|simple_content_access|simple content access' \$base_dir/var/log/candlepin/audit.log \$base_dir/var/log/httpd/foreman-ssl_access_ssl.log \$base_dir/var/log/candlepin/candlepin.log \$base_dir/var/log/candlepin/error.log \$base_dir/sos_commands/insights/insights-client-dump/data/insights_commands/sudo_-iu_postgres_.usr.bin.psql_-d_candlepin_-c_select_displayname_content_access_mode_from_cp_owner_--csv"
		log "from candlepin, foreman and insights logs"
                log "---"
                log_cmd "egrep -m 5 --color=ALWAYS 'org_environment|simple_content_access|simple content access' $base_dir/var/log/candlepin/audit.log $base_dir/var/log/httpd/foreman-ssl_access_ssl.log $base_dir/var/log/candlepin/candlepin.log $base_dir/var/log/candlepin/error.log $base_dir/sos_commands/insights/insights-client-dump/data/insights_commands/sudo_-iu_postgres_.usr.bin.psql_-d_candlepin_-c_select_displayname_content_access_mode_from_cp_owner_--csv 2>/dev/null"
                log "---"
                log

		log "// ERROR on candlepin log - candlepin.log"
		log "{ for mylog in \`ls -rt \$base_foreman/var/log/candlepin/candlepin.log*\`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c"
		log "---"
		if [ -f "$base_foreman/var/log/candlepin/candlepin.log" ];then
			{ for mylog in `ls -rt $base_foreman/var/log/candlepin/candlepin.log*`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c | tail -100 &>> $FOREMAN_REPORT
		else
			cmd="echo 'File candlepin.log not found.'"
		fi
		log "---"
		log

		log "// ERROR on candlepin log - error.log"
		log "{ for mylog in \`ls -rt \$base_foreman/var/log/candlepin/error.log*\`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c"
		log "---"
		if [ -f "$base_foreman/var/log/candlepin/error.log" ];then
			{ for mylog in `ls -rt $base_foreman/var/log/candlepin/error.log*`; do zcat $mylog 2>/dev/null || cat $mylog; done; } | grep ERROR | cut -d ' ' -f1,3- | uniq -c | tail -100 &>> $FOREMAN_REPORT
		else
			cmd="echo 'File candlepin/error.log not found.'"
		fi
		log "---"
		log

		log "// latest entries on error.log"
		log "tail -30 \$base_foreman/var/log/candlepin/error.log"
		log "---"
		log_cmd "tail -30 $base_foreman/var/log/candlepin/error.log"
		log "---"
		log

		log "// candlepin storage consumption"
		log "cat \$base_dir/sos_commands/candlepin/du_-sh_.var.lib.candlepin"
		log "---"
		log_cmd "cat $base_dir/sos_commands/candlepin/du_-sh_.var.lib.candlepin | egrep --color=always '^|G'"
		log "---"
		log

		log "Note:  In Satellite 6.4, activemq-artemis replaced hornetq.  Apache ActiveMQ Artemis is an open source project for an asynchronous messaging system."
		log

		log "// postgres idle processed (candlepin)"
		log "grep ^postgres \$base_dir/ps | grep idle$ | grep \"candlepin candlepin\" | wc -l"
		log "---"
		log_cmd "grep ^postgres $base_dir/ps | grep idle$ | grep \"candlepin candlepin\" | wc -l"
		log "---"
		log

		log "// cpdb"
		log "cat \$base_foreman/var/log/candlepin/cpdb.log"
		log "---"
		log_cmd "cat $base_foreman/var/log/candlepin/cpdb.log | tail -100"
		log "---"
		log

	  fi




          log_tee "## katello"
          log

          if [ ! -d "$base_dir/sos_commands/katello" ] && [ ! -f "$base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf" ]; then

                log "katello not found"
                log

          else

            log "Katello is a Foreman plug-in for subscription and repository management. It provides a means to subscribe to Red Hat repositories and download content. You can create and manage different versions of this content and apply them to specific systems within user-defined stages of the application life cycle."
            log

                log "// katello_event_queue (foreman-tasks / dynflow is running?)"
		log "grep -E -h '(  queue|  ===|katello_event_queue)' \$base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate"
                log "---"
		log_cmd "egrep -v ':1.0|Anonymous connections disabled|certificate required' $base_dir/sos_commands/katello/qpid-stat_-q_--ssl-certificate | egrep -v '0     0      0       0      0        0'"
                log "---"
                log

                log "// katello.conf configuration"
                log "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout \$base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf'"
                log "---"
                log_cmd "grep 'KeepAlive\b\|MaxKeepAliveRequests\|KeepAliveTimeout $base_dir/etc/httpd/conf.d/05-foreman-ssl.d/katello.conf'"
                log "---"
                log

                log "// katello timeouts"
                log "egrep timeout \$base_dir/etc/foreman/plugins/katello.yaml"
                log "---"
                log_cmd "egrep timeout $base_dir/etc/foreman/plugins/katello.yaml"
                log "---"
                log

          fi



          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep elasticsearch`" ] || [ ! "`egrep -i 'elasticsearch' $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ] && [ ! -e "$base_dir/etc/elasticsearch" ]; then

	    nop=1

          else

	    
            log_tee "## elasticsearch (deprecated in 6.2)"
            log

            log "Elasticsearch is a distributed, free and open search and analytics engine for all types of data, including textual, numerical, geospatial, structured, and unstructured."
            log



                #SERVICE_NAME='elasticsearch'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='elasticsearch'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            log "// satellite log errors"
            log "from katello-installer logs"
            log "---"
            log_cmd "egrep -h elasticsearch $base_dir/sysmgmt/{katello-installer.log,satellite.log,capsule.log} | egrep -i 'fail|error' | tail -50"
            log "---"
            log

            log "// elasticsearch log errors"
            log "from elasticsearch logs"
            log "---"
            log_cmd "egrep -hi 'fail|error|warn' $base_dir/var/log/elasticsearch | sort | tail -50"
            log "---"
            log


	  fi


          log_tee "## virt-who"
          log

          log "The virt-who agent interrogates the hypervisor infrastructure and provides the host/guest mapping to the subscription service. It uses read-only commands to gather the host/guest associations for the subscription services. This way, the guest subscriptions offered by a subscription can be unlocked and available for the guests to use."
          log

#          if [ "`grep cmd=virt-who $base_dir/var/log/httpd/foreman-ssl_access_ssl.log`" ]; then
                log "// virt-who update sources"
                log "grep cmd=virt-who \$base_dir/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1}' | sort -u"
                log "---"
                export GREP_COLORS='ms=01;33'   # temporarily change hilight color to yellow
                log_cmd "grep cmd=virt-who $base_dir/var/log/httpd/foreman-ssl_access_ssl.log | awk '{print \$1}' | sort -u | egrep --color=always '^|$IPADDRLIST'"
                export GREP_COLORS='ms=01;31'
                log "---"
                log
#          fi

          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep virt-who`" ] || [ ! "`egrep -i 'virt-who' $base_dir/chkconfig $base_dir/installed_rpms $base_dir/ps $base_dir/var/log/rhsm/rhsm.log 2>/dev/null | head -1`" ] && [ ! -f "$base_dir/etc/sysconfig/virt-who" ] && [ ! -d "$base_dir/etc/virt-who.d" ]; then


                log "virt-who not found"
                log

          else


                #SERVICE_NAME='virt-who'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='virt-who'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

                log "// number of duplicated hypervisors"
                log "grep \"is assigned to 2 different systems\" \$base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u | wc -l"
                log "---"
                log_cmd "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u | wc -l"
                log "---"
                log

                log "// duplicated hypervisors list"
                log "grep \"is assigned to 2 different systems\" \$base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u"
                log "---"
                log_cmd "grep \"is assigned to 2 different systems\" $base_dir/var/log/rhsm/rhsm.log | awk '{print \$9}' | sed -e \"s/'//g\" | sort -u"
                log "---"
                log

                log "// Sending updated Host-to-guest"
                log "grep \"Sending updated Host-to-guest\" \$base_dir/var/log/rhsm/rhsm.log"
                log "---"
                log_cmd "grep \"Sending updated Host-to-guest\" $base_dir/var/log/rhsm/rhsm.log | egrep \"`date +'%Y' --date='-2 months'`|`date +'%Y'`\""
                log "---"
                log

                log "// virt-who default configuration"
                log "grep -v ^# \$base_dir/etc/sysconfig/virt-who | grep -v ^$"
                log "---"
                log_cmd "grep -v ^# $base_dir/etc/sysconfig/virt-who | grep -v ^$"
                log "---"
                log

                log "// virt-who configuration"
                log "ls -l \$base_dir/etc/virt-who.d"
                log "---"
                log_cmd "ls -l $base_dir/etc/virt-who.d"
                log "---"
                log

                log "// duplicated server entries on virt-who configuration"
                log "grep -h ^server \$base_dir/etc/virt-who.d/*.conf | sort | uniq -c"
                log "---"
                log_cmd "grep -h ^server $base_dir/etc/virt-who.d/*.conf | sort | uniq -c"
                log "---"
                log

                log "// RHSM Warnings - virt-who"
                log "grep WARNING \$base_dir/var/log/rhsm/rhsm.log"
                log "---"
                log_cmd "grep WARNING $base_dir/var/log/rhsm/rhsm.log | egrep 'virt-who' | tail -100"
                log "---"
                log

                log "// virt-who errors in messages log and journalctl"
                log "---"
                log_cmd "egrep -hi virt-who $base_dir/sysmgmt/{journal.log,messages} | egrep -i 'fail|error'"
                log "---"
                log

                log "// Latest 30 hypervisors tasks"
                log "grep -E '(^                  id|Hypervisors)' \$base_dir/sos_commands/foreman/foreman_tasks_tasks | sed -e 's/,/ /g' | sort -rk6 | head -n 30 | cut -d\| -f3,4,5,6,7"
                log "---"
                log_cmd "grep -E '(^                  id|Hypervisors)' $base_dir/sos_commands/foreman/foreman_tasks_tasks | sed -e 's/,/ /g' | sort -rk6 | head -n 30 | cut -d\| -f3,4,5,6,7 | egrep -i --color=always \"^|warning\""
                log "---"
                log


                  if [ "`file $base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF | head -1`" ]; then
                    log "// virt-who files with DOS line endings"
                    log "file \$base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF"
                    log "---"
                    log_cmd "file $base_dir/etc/virt-who.d/*.conf | grep ASCII | grep CRLF"
                    log "---"
                    log
                  fi

                log "// virt-who configuration content files (showing hidden characters)"
                log "for b in \$(ls -1 \$base_dir/etc/virt-who.d/*.conf); do echo; echo \$b; echo \"===\"; cat -vet \$b; echo \"===\"; done"
                log "---"
                log_cmd "for b in \$(ls -1 $base_dir/etc/virt-who.d/*.conf); do echo; echo \$b; echo \"===\"; cat -vet \$b; echo \"===\"; done"
                log "---"
                log

          fi

          log_tee "## named (bind)"
          log

          log "The bind package installs the named DNS service, which Satellite uses for network (PXEBoot) provisioning."
          log

          if [ "$(egrep systemd-resolved $base_dir/sos_commands/systemd/systemctl_list-unit-files)" ]; then
                log "// DNS caching service status (RHEL 8+)"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h named $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v ^systemd-hostnamed | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -ir '^\* named.service|^\● named.service' $base_dir/sos_commands/systemd/systemctl_status_--all -A 20 -h | sed -n '/named.service/,/\.service/p' | sed '$ d' | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log
          fi

          if [ ! "`egrep '^\* named' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status`" ] || [ ! -f "$base_dir/etc/zones.conf" ] && [ ! -f "$base_dir/etc/named.conf" ] && [ "`egrep ^named $base_dir/chkconfig`" == '' ]; then

                log "bind not found"
                log

          else

                #SERVICE_NAME='named'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v 'setup|hostnamed' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|setup|hostnamed' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='named'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            log "// zone configuration"
            log "cat \$base_dir/etc/zones.conf"
            log "---"
            log_cmd "cat $base_dir/etc/zones.conf"
            log "---"
            log

        if [ "`egrep '^dns: true$' $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}`" ]; then
            log "// Satellite-DNS configuration"
            log "info from /etc/foreman-installer/scenarios.d/"
            log "---"
            log_cmd "egrep dns $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml} | egrep -v infoblox | egrep --color=always '^|:  dns: true'"
	    log
            log_cmd "egrep dns $base_dir/etc/foreman-installer/scenarios.d/*-answers.yaml | egrep infoblox | egrep --color=always '^|infoblox: true'"
            log "---"
            log
	fi

           log "// check dns interfaces in satellite-answers"
           log "grep _interface: \$base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml | egrep 'dns'"
           log "---"
           log_cmd "grep _interface: $base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml"
           log "---"
           log

          fi

          log_tee "## dhcpd"
          log

          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep dhcpd`" ] || [ ! -f "$base_dir/etc/dhcp/dhcpd.conf" ] && [ "`egrep ^dhcpd $base_dir/chkconfig`" == '' ]; then

                log "dhcpd not found"
                log

          else

            log "The dhcp package installs the dhcpd service, which Satellite uses for network (PXEBoot) provisioning."
            log


                #SERVICE_NAME='dhcpd'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='dhcpd'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            log "// dhcp configuration"
            log "cat \$base_dir/etc/dhcp/dhcpd.conf"
            log "---"
            log_cmd "cat \$base_dir/etc/dhcp/dhcpd.conf"
            log "---"
            log

	if [ "`egrep '^dhcp: true$' $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}`" ]; then
            log "// Satellite-DHCP configuration"
            log "info from /etc/foreman-installer/scenarios.d/"
            log "---"
            log_cmd "egrep dhcp $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml} | egrep -v 'infoblox|::' | egrep --color=always '^|dhcp: true'"
            log
            log_cmd "egrep dhcp $base_dir/etc/foreman-installer/scenarios.d/*-answers.yaml | egrep infoblox | egrep --color=always '^|infoblox: true'"
            log "---"
            log
	fi

	if [ "`egrep '^dns: true$' $base_dir/etc/foreman-installer/scenarios.d/{satellite-answers.yaml,capsule-answers.yaml}`" ]; then
          log "// check dhcp interfaces in satellite-answers"
          log "grep _interface: \$base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml | egrep 'dhcp'"
          log "---"
          log_cmd "grep _interface: $base_dir/etc/foreman-installer/scenarios.d/satellite-answers.yaml | egrep 'dhcp'"
          log "---"
          log
	fi

          fi



	  log_tee "## Subscription Watch"
	  log

	  if [ ! -f "$base_dir/etc/foreman-installer/scenarios.d/satellite.migrations/*-add-inventory-upload.rb" ] || [ ! "`egrep \"tfm-rubygem-foreman_rh_cloud|tfm-rubygem-foreman_inventory_upload\" $base_dir/sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V`" ]; then

		log "subscription watch not found"
		log

	  else

	    log "Subscription watch provides unified reporting of Red Hat Enterprise Linux subscription usage information across the constituent parts of your hybrid infrastructure, including physical, virtual, on-premise, and cloud. This unified reporting model enhances your ability to consume, track, report, and reconcile your Red Hat subscriptions with your purchasing agreements and deployment types."
	    log

	    log "The use of Satellite as the data collection tool is useful for customers who have specific needs in their environment that either inhibit or prohibit the use of the Insights agent or the Subscription Manager agent for data collection."
	    log

	    log "// is the subscription watch foreman plugin installed?"
	    log "---"
	    log_cmd "egrep \"tfm-rubygem-foreman_rh_cloud|tfm-rubygem-foreman_inventory_upload\" $base_dir/installed-rpms 2>&1"
	    log_cmd "cat $base_dir/etc/foreman-installer/scenarios.d/satellite.migrations/*-add-inventory-upload.rb"
	    log "---"
	    log

	    log "Note:  tfm-rubygem-foreman_rh_cloud is the current package for the Subscription Watch plugin.  tfm-rubygem-foreman_inventory_upload is the old one."
	    log

	  fi


          if [ ! "`egrep '^\*' $base_dir/sysmgmt/services.txt $base_dir/sos_commands/foreman/foreman-maintain_service_status | egrep 'osbuild|lorax'`" ] || [ ! "`egrep -i 'osbuild|lorax' $base_dir/installed_rpms $base_dir/ps 2>/dev/null | head -1`" ]; then

		nop=1


          else

	    log_tee "## osbuild"
	    log


            log "Composer Image Builder (previously known as Lorax Composer) helps custoemrs create customized system images of RHEL."
            log

                #SERVICE_NAME='osbuild'
                #log "// $SERVICE_NAME service status"
                #log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                #log "---"
                #log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                #log
                #if [ "$(egrep $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_status_--all | egrep '^\*' | egrep '\.service')" ]; then IFS=$'\n'; COPY_FLAG=0;SERVICE_INFO=''; for i in $(cat $base_dir/sos_commands/systemd/systemctl_status_--all | sed s'/\●/\*/'g | egrep -v "\`|\|"); do START_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -' | egrep -v 'sentinel|\@|mongos' | egrep "$SERVICE_NAME"); STOP_CHECK=$(echo $i | egrep '^\*' | egrep '\.service -|\.automount -|\.device -|\.mount -|\.net -|\.path -|\.slice -|\.socket -|\.swap -|\.target -|\.timer -' | egrep -v dynflow);  if [ "$START_CHECK" ]; then COPY_FLAG=1; elif [ "$STOP_CHECK" ]; then COPY_FLAG=0; fi;  if [ "$COPY_FLAG" == "1" ]; then SERVICE_INFO=$(echo -e "$SERVICE_INFO""\n""$i" | egrep .); fi; done; else SERVICE_INFO="service not found"; fi
                #log_cmd "echo -e \"$SERVICE_INFO\" | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                #log "---"
                #log

                SERVICE_NAME='osbuild'
                log "// $SERVICE_NAME service status"
                log "from files \$base_dir/sos_commands/systemd/systemctl_list-unit-files and \$base_dir/sos_commands/systemd/systemctl_status_--all"
                log "---"
                log_cmd "egrep -h $SERVICE_NAME $base_dir/sos_commands/systemd/systemctl_list-unit-files $base_dir/chkconfig | egrep -v '\@|\-init|socket' | egrep --color=always '^|failed|inactive|activating|deactivating|disabled|masked|5:off'"
                log
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                SERVICE_NAME='lorax'
                log_cmd "egrep -v '\|-' $base_dir/sysmgmt/services.txt | egrep \"^\* $SERVICE_NAME\" -A 20 | sed -n \"/^\* $SERVICE_NAME/,/^\*/p\" | sed '$ d' | sed s'/^\*/\n\*/'g | egrep --color=always '^|failed|inactive|activating|deactivating|masked|plugin:demo\, DISABLED'"
                log "---"
                log

            log "// osbuild repos"
            log "---"
            log "ls \$base_dir/etc/osbuild-composer/repositories"
            log
            log_cmd "ls $base_dir/etc/osbuild-composer/repositories"
            log "---"
            log
            log "Note:  Check KCS 5773421 for more info about osbuild repos."
            log

            log "// osbuild proxy info"
            log "---"
            log "egrep -i proxy \$base_dir/etc/systemd/system/osbuild-composer.service.d/proxy.conf"
            log
            log_cmd "egrep -i proxy $base_dir/etc/systemd/system/osbuild-composer.service.d/proxy.conf"
            log

            log "// messages log"
            log "---"
            log "egrep osbuild \$base_dir/sysmgmt/messages"
            log
            log_cmd "egrep osbuild $base_dir/sysmgmt/messages | tail -50"
            log "---"
            log

          fi




  if [ "`which insights 2>/dev/null`" != "" ]; then
	log_tee
	log_tee "## Insights"
	log
	insights run -p shared_rules -F $sos_path | egrep -v SSSSS | egrep --color=always "^|\[FAIL\]" | sed s'/\\n/\n/'g >> $FOREMAN_REPORT
	log
	insights run -p telemetry    -F $sos_path | egrep -v SSSSS | egrep --color=always "^|\[FAIL\]" | sed s'/\\n/\n/'g >> $FOREMAN_REPORT
        echo "done."
  fi

  if [ "$XSOS_REPORT" == "true" ]; then
        echo
        echo "Calling xsos..."
        xsos -a $sos_path 2>/dev/null > xsos_results.txt
        log
  fi


#  exit

  echo
  echo
  echo "## The output has been saved in these locations:"

  # generate local copy with or without ansi color codes

  cat $FOREMAN_REPORT | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tr -d '\033' | sed 's/\[K//g' | sed 's/\[m//g' > ./report_${USER}_$final_name.log

  if [ "$ANSI_COLOR_CODES" == "false" ]; then
	# cat $FOREMAN_REPORT | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' > ./report_${USER}_$final_name.log
	rm -f $FOREMAN_REPORT 2>/dev/null
  else
	mv $FOREMAN_REPORT ./report_color_${USER}_$final_name.log
	chmod 666 ./report_color_${USER}_$final_name.log
	# cat ./report_color_${USER}_$final_name.log | sed -r 's/\x1B\[(;?[0-9]{1,3})+[mGK]//g' > ./report_${USER}_$final_name.log
  fi

  chmod 666 ./report_${USER}_$final_name.log


  # either move or copy report to /tmp directory
  if [ "$COPY_TO_CURRENT_DIR" == "false" ] && [ "$OPEN_IN_VIM_RO_LOCAL_DIR" == "false" ]; then
	mv report_${USER}_$final_name.log /tmp/
  elif [ "$ANSI_COLOR_CODES" == "true" ]; then
	mv report_${USER}_$final_name.log /tmp/
	echo "    ./report_color_${USER}_$final_name.log"
  else
	cp -f report_${USER}_$final_name.log /tmp/
	echo "    ./report_${USER}_$final_name.log"
  fi

  echo "    /tmp/report_${USER}_$final_name.log"
  echo ""





}


# Main

if [ "$1" == "" ]; then
  echo "Please supply the path of the sosreport that you would like to analyze.  For example:"
  echo "    $0 01234567/sosreport"
  exit 1
fi

main $1

# the following code will open the requested report
# in the user's editor of choice
# if none is defined, "less" will be chosen.

if [ ! "$EDITOR" ]; then
   EDITOR=`which less`
fi

if [ "$OPEN_IN_VIM_RO_LOCAL_DIR" == "true" ]; then
   if [ "$ANSI_COLOR_CODES" == "false" ]; then
	$EDITOR -R $MYPWD/report_${USER}_$final_name.log
   else
	less -R $MYPWD/report_color_${USER}_$final_name.log
   fi
fi

if [ "$OPEN_IN_EDITOR_TMP_DIR" == "true" ]; then
   $EDITOR /tmp/report_${USER}_$final_name.log
fi

if [ -f "$base_dir/var/log/leapp/leapp-report.txt" ]; then
    ln -s "$base_dir/var/log/leapp/leapp-report.txt" leapp-report.txt
fi

if [ "`egrep -i selinux $base_dir/sysmgmt/messages | egrep confidence`" ]; then
	egrep -i selinux $base_dir/sysmgmt/messages | egrep confidence | sed s'/#012/\n/'g &> setroubleshoot_messages.txt
fi
