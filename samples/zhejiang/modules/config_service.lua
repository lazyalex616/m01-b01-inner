package.preload[ "config_service" ] = assert( (loadstring or load)(
"return {\"arch\",\"dns\",\"tuple\",\"sys\",\"svroper\",\"shell\",\"operdata\",\"svrdata\",\"sig\",\"dmpapp\",\"ct\",\"osinfo\",\"sigcollect\",\"http\",\"upgrade\",\"dpinfo\",\"http_rule\",\"devinfo\",\"lanhost\",\"lanhoststats\",\"wanstats\",\"diagnose\",\"hredirect\",\"capi\",\"pscan\",\"rawpkt\",\"hotpatch\",\"topo\",\"mdns\",\"upnp\",\"pktpolicy\",\"wandns\",\"pcap_dump\",\"dhcp\",\"oscloud\",\"pqprobe\",\"dumh\",\"https\",\"postmsg\",\"sec_data\",\"domain_dip\",\"sec_camera\",\"appsig_bin\",\"apprule\",\"appinfo\",\"http_imei\",\"appctrl\",\"appuse\",\"appmlp\"}\
"
, '@'.."./config_service.lua" ) )
