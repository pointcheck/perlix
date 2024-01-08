#!/usr/local/bin/perl

#
# This is a demo to illustrate how easy it is to draw a rudimentary window using pure X11 protocol
# i.e. by talking directly to X server through a socket. This work was inspired by article on Habr:
# https://habr.com/ru/articles/712376/
#
# Written by Ruslan Zalata <rz@fabmicro.ru>. 2024, Tyumen, Russia.
#


use POSIX;
use Fcntl;
use FileHandle;
use Socket;

my ($host, $display, $screen) = split(/\:|\./, $ENV{DISPLAY});

my $x_fd;

if($host =~ /unix/ || !$host) {
	my $sock_name = "/tmp/.X11-unix/X".$display;
	print "Connecting to X at UNIX socket: $sock_name, display: $display, screen: $screen\n";

	socket($x_fd, PF_UNIX, SOCK_STREAM, 0) || die "Can't create socket - $!";

	$paddr = sockaddr_un($sock_name);

	connect($x_fd, $paddr) || die "Can't connect to $sock_name - $!";

} else {

	my $remote = inet_aton($host)  || die "No such host ${host} - $!\n";
	my $port = 6000 + $display;

	print "Connecting to X over TCP at host: $host, port: $port, display: $display, screen: $screen\n";

	socket($x_fd, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || die "Can't create socket - $@";

	my $paddr = sockaddr_in($port, $remote);

	connect($x_fd, $paddr) || die "Can't connect to $host:$port - $@";
}

print "Connection established, x_fd: $x_fd\n";

my ($x_auth_fd, $x_auth_file, $x_data);
my ($data, $read_bytes, $written_bytes);
my ($x_auth_family, $x_auth_addr_len, $x_auth_addr);
my ($x_auth_number_len, $x_auth_number);
my ($x_auth_name_len, $x_auth_name);
my ($x_auth_data_len, $x_auth_data);

if(-f "$ENV{XAUTHORITY}") {
	$x_auth_file = $ENV{XAUTHORITY};
} elsif(-f "$ENV{HOME}/.Xauthority") {
	$x_auth_file = $ENV{HOME}."/.Xauthority";
} else {
	print "Cannot find X auth file!\n";
	exit;
}

print "Using Xauth file: $x_auth_file\n";

open($x_auth_fd, "<", $x_auth_file) || die "Failed to open Xauth file: $x_auth_file - $@\n";
binmode $x_auth_fd;


while(1) {
	$read_bytes = sysread($x_auth_fd, $data, 4);

	if($read_bytes == 0) { ## EOF
		last; 
	}

	if($read_bytes < 4) {
		die "Something went wrong while reading Xauth file, read_bytes: $read_bytes\n";
	}

	($x_auth_family, $x_auth_addr_len) = unpack('nn', $data); 

	$read_bytes = sysread($x_auth_fd, $data, $x_auth_addr_len + 2);
	if($read_bytes < $x_auth_addr_len + 2) {
		die "Something went wrong while reading Xauth file, read_bytes: $read_bytes\n";
	}

	($x_auth_addr, $x_auth_number_len) = unpack('a'.$x_auth_addr_len.'n', $data); 

	$read_bytes = sysread($x_auth_fd, $data, $x_auth_number_len + 2);
	if($read_bytes < $x_auth_number_len + 2) {
		die "Something went wrong while reading Xauth file, read_bytes: $read_bytes\n";
	}

	($x_auth_number, $x_auth_name_len) = unpack('a'.$x_auth_number_len.'n', $data); 

	$read_bytes = sysread($x_auth_fd, $data, $x_auth_name_len + 2);
	if($read_bytes < $x_auth_name_len + 2) {
		die "Something went wrong while reading Xauth file, read_bytes: $read_bytes\n";
	}

	($x_auth_name, $x_auth_data_len) = unpack('a'.$x_auth_name_len.'n', $data); 

	$read_bytes = sysread($x_auth_fd, $data, $x_auth_data_len);
	if($read_bytes < $x_auth_data_len) {
		die "Something went wrong while reading Xauth file, read_bytes: $read_bytes\n";
	}

	$x_auth_data = $data;
	
	print "Xauth: family = $x_auth_family, x_auth_addr = $x_auth_addr, x_auth_number = $x_auth_number, x_auth_name = $x_auth_name, x_auth_data = ".to_hex_str($x_auth_data)."\n";

	if($x_auth_addr eq $host && $x_auth_number == $display) {
		print "Xauth cookie found.\n";
	}
}

close($x_auth_fd);

# Pad auth data
$x_auth_name = pad_to_32bit($x_auth_name);
$x_auth_data = pad_to_32bit($x_auth_data);

#my $x_auth_req = make_x_req(1, 0,
#	pack('CCSSSSSa'.length($x_auth_name).'a'.length($x_auth_data), 
#		0x6C, 0x00, 11, 0, $x_auth_name_len, $x_auth_data_len, 0, $x_auth_name, $x_auth_data));

my $x_auth_req = pack('CCnnnnna'.length($x_auth_name).'a'.length($x_auth_data), 
		0x42, 0x00, 11, 0, $x_auth_name_len, $x_auth_data_len, 0, $x_auth_name, $x_auth_data);


$written_bytes = syswrite($x_fd, $x_auth_req, length($x_auth_req));

if($written_bytes < 1) {
	print "X server write error: $!\n";
} 

print "XAuth req sent $written_bytes bytes: ".to_hex_str($x_auth_req)."\n";

sleep(1);

$read_bytes = sysread($x_fd, $x_data, 1024*100);

if($read_bytes < 1) { 
	print "Server closed connection unexpectedly!\n";
	exit;
}

print "Response read $read_bytes bytes.\n";

my ($x_auth_code) = unpack("C", $x_data);

print "Response code: $x_auth_code\n";

if($x_auth_code eq 0) {
	## XAuth fail
	my ($text_len, $x_ver_maj, $x_ver_min, $x_data_len, $text) = unpack("xCnnna*", $x_data);
	print "Error text ($text_len): $text\n";
	print "Server version: $x_ver_maj.$x_ver_min\n";
	exit;
}

if(!($x_auth_code eq 1)) {
	print "Unexpected server response code!\n";
	exit;
}

### Parse setup response ###

my ($x_ver_maj, $x_ver_min, $x_data_len, $x_release_number, $x_resourse_id_base, $x_resourse_id_mask,
	$x_motion_buffer, $x_vendor_len, $x_max_req_len, $x_num_of_screens, $x_num_of_formats,
	$x_min_keycode, $x_max_keycode, $x_data_rest) = unpack("xxnnnNNNNnnCCxxxxCCx4a*", $x_data);

my $x_vendor_len_pad_size = ceil($x_vendor_len / 4) * 4 - $x_vendor_len;

my ($x_vendor, $x_data_rest) = unpack("a".$x_vendor_len."x".$x_vendor_len_pad_size."a*", $x_data_rest);

print "Server response:
	x_ver_maj:		$x_ver_maj
	x_ver_min:		$x_ver_min
	x_data_len:		$x_data_len
	x_release_number:	$x_release_number
	x_resourse_id_base:	$x_resourse_id_base
	x_resourse_id_mask:	$x_resourse_id_mask
	x_motion_buffer:	$x_motion_buffer
	x_vendor_len:		$x_vendor_len
	x_max_req_len:		$x_max_req_len
	x_num_of_screens:	$x_num_of_screens
	x_num_of_formats:	$x_num_of_formats
	x_min_keycode:		$x_min_keycode
	x_max_keycode:		$x_max_keycode
	x_vendor:		$x_vendor
";

my $x_format;
for(my $i = 0; $i < $x_num_of_formats; $i++) {
	($x_format, $x_data_rest) = unpack("Qa*", $x_data_rest);
}

my ($s_root_windows, $s_color_map, $s_white_pix, $s_black_pix, $s_cur_input_max,
	$s_width_pix, $s_height_pix, $s_width_mm, $s_height_mm, $s_min_inst_maps, $s_max_inst_maps,
	$s_root_visual, $s_backing_store, $x_data_rest) = unpack("NNNNNnnnnnnNCa*", $x_data_rest); 

print "Root windows:
	s_root_windows:		$s_root_windows
	s_color_map:		$s_color_map
	s_white_pix		$s_white_pix
	s_black_pix:		$s_black_pix
	s_cur_input_max:	$s_cur_input_max
	s_width_pix:		$s_width_pix
	s_height_pix		$s_height_pix
	s_width_mm:		$s_width_mm
	s_height_mm:		$s_height_mm
	s_min_inst_maps:	$s_min_inst_maps
	s_max_inst_maps:	$s_max_inst_maps
	s_root_visual:		$s_root_visual
";


### Create new window ###

my $main_win_id = $x_resourse_id_base + 1;

$x_create_win_req = pack("CCnNNnnnnnnNN", 1, 0, 8, $main_win_id, $s_root_windows, 200, 200, 300, 300, 10, 1, 0, 0);
	
$written_bytes = syswrite($x_fd, $x_create_win_req, length($x_create_win_req));

if($written_bytes < 1) {
	print "X server write error: $!\n";
} 

print "Create win req sent $written_bytes bytes: ".to_hex_str($x_create_win_req)."\n";


### Make it visible ###

$x_map_win_req = pack("CCnN", 8, 0, 2, $main_win_id);

$written_bytes = syswrite($x_fd, $x_map_win_req, length($x_map_win_req));

if($written_bytes < 1) {
	print "X server write error: $!\n";
} 

print "Map win req sent $written_bytes bytes: ".to_hex_str($x_create_win_req)."\n";


### Read events ###

while(1) {
	$read_bytes = sysread($x_fd, $x_data, 1024*100);

	if($read_bytes < 1) { 
		print "Server closed connection unexpectedly!\n";
		exit;
	}

	print "Response read $read_bytes bytes.\n";

	my ($x_auth_code) = unpack("C", $x_data);

	print "Response code: $x_auth_code\n";
}


sub make_x_req {
	my ($cmd0, $cmd1, $req) = @_;

	my $pad_size = ceil(length($req) / 4) * 4 - length($req);

	if($pad_size > 0) {
		return pack("CCSa".length($req)."x".$pad_size, $cmd0, $cmd1, (length($req) + $pad_size) / 4 + 1, $req);
	} else {
		return pack("CCSa".length($req), $cmd0, $cmd1, length($req) / 4 + 1, $req);
	}
}

sub pad_to_32bit {
	my $str = shift @_;
	my $padded_len = ceil(length($str) / 4) * 4;
	return pack("a".$padded_len, $str); 
}


sub to_hex_str {
	my $str = shift @_;
	my $hex_str = "";
	for(my $i = 0; $i < length($str); $i++) { $hex_str .= sprintf("0x%02x ", unpack("x$i"."C",$str)); }
	return $hex_str;
}

