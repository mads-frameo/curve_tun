

-record(curve_tun_lsock, { lsock :: port (), options :: list() }).
-record(curve_tun_socket, { pid :: pid() }).


-type curve_tun_socket() :: #curve_tun_socket{}.

-type socket_connect_option() :: gen_tcp:connect_option().
-type connect_option()        :: socket_connect_option() | curve_tun_option().

-type listen_option()            :: socket_listen_option() | curve_tun_option().
-type socket_listen_option()     :: gen_tcp:listen_option().

-type curve_tun_option() ::
     {packet, 0|1|2|4}
   | {active, once|true|false}
   | {metadata, [metadata_item()]}
   | {peer_public_key, public_key()}
   | {key, private_key()}
   .

-type public_key() :: binary().
-type private_key() :: binary().

-type metadata_item() :: { atom(), string() }.

-type reason()            :: term().
-type reply()             :: term().
-type msg()               :: term().
-type from()              :: term().
-type host()		  :: inet:ip_address() | inet:hostname().
