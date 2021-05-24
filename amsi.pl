#! c:\perl\bin\perl.exe
#-----------------------------------------------------------
# amsi.pl
# Plugin for Registry Ripper, NTUSER.DAT 
# AMSI Persistence 
#
# Change history
# 20210524 - (2021-05-24) created by Krzysztof Gajewski (gajos112@gmail.com)
#  
#-----------------------------------------------------------
package amsi;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20210524);

sub getConfig{return %config}
sub getShortDescr {
	return "Look for AMSI (Antimalware Scan Interface) persistence";	
}
sub getDescr{}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching AMSI v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	
	::rptMsg("");
 
	my $key;
	my $key_to_class;		
	
	my $key_path = "Microsoft\\AMSI\\Providers";  

	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				
				::rptMsg("Provider Name: ".$name);
				my @vals = $s->get_list_of_values();
					if (scalar(@vals) > 0) {
						foreach my $v (@vals) {
							my $data = $v->get_data();
							::rptMsg("Data: ".$data);
							
							my $key_path_DLL = "Classes\\CLSID\\" . $name . "\\InProcServer32";
							::rptMsg("DLL: ".$key_path_DLL);
							
							if ($key_to_class = $root_key->get_subkey($key_path_DLL)) {
								
								my @vals2 = $key_to_class->get_list_of_values();
								foreach my $s (@vals2) {
									
									my $name = $s->get_name();
									my $data = $s->get_data();
									if ($name eq ""){
										::rptMsg("  -> Path to the file: ".$data);
									}
									else{
										::rptMsg("  -> ".$name.": ".$data);
									}
								}
							}
						}
					}
					
				::rptMsg("LastWrite Time: ".::getDateFromEpoch($key->get_timestamp())." (UTC)");
				::rptMsg();
			}
	}
	
	else {
			::rptMsg($key." has no values.");
	}	
}

1;


