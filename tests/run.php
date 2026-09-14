<?php
/** Local public-ability tests. Every HTTP and mail transport is an in-memory fixture. */
define( 'ABSPATH', rtrim( getenv( 'WORDPRESS_TEST_ROOT' ) ?: '/tmp/workspace-wp-runtime', '/' ) . '/' );
define( 'WPINC', 'wp-includes' );
class WP_Error {
 public function __construct( public string $code, public string $message ) {}
 public function get_error_message() { return $this->message; }
}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function add_action( ...$args ) {}
function current_user_can( $cap ) { return 'manage_options' === $cap; }
function wp_register_ability( $name, $args ) { $GLOBALS['abilities'][$name] = $args; }
function get_option( $name, $default = null ) { return array( 'service_account' => array( 'client_email' => 'service@example.com', 'private_key' => 'unused fixture' ), 'impersonate_email' => 'owner@example.com' ); }
function get_transient( $key ) { return array( 'token' => 'fixture', 'expires' => time() + 3600 ); }
function wp_remote_request( $url, $args ) { $GLOBALS['requests'][] = array( 'url'=>$url, 'args'=>$args ); return ($GLOBALS['http_fixture'])( $url, $args ); }
function wp_remote_post( ...$args ) { throw new RuntimeException( 'Token network access is forbidden in this test.' ); }
function wp_mail( ...$args ) { throw new RuntimeException( 'Mail delivery is forbidden in this test.' ); }
function wp_remote_retrieve_response_code( $r ) { return $r['code']; }
function wp_remote_retrieve_body( $r ) { return $r['body']; }
function wp_json_encode( $value ) { return json_encode( $value ); }
function add_query_arg( $query, $url ) { return $url . '?' . http_build_query( $query ); }
function sanitize_email( $value ) { return filter_var($value,FILTER_VALIDATE_EMAIL) ?: ''; }
function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
function wp_kses_post( $value ) { return $value; }
function wp_strip_all_tags( $value ) { return strip_tags( $value ); }
function wp_generate_password( ...$args ) { return 'fixtureboundary'; }
function invoke( $name, $input ) { return $GLOBALS['abilities'][$name]['execute_callback']( $input ); }
function expect( $condition, $message ) { if ( ! $condition ) { throw new RuntimeException( $message ); } }
function response( $data, $code = 200 ) { return array( 'code'=>$code, 'body'=>json_encode( $data ) ); }
require dirname( __DIR__ ) . '/mcp-abilities-workspace.php';
mcp_register_email_abilities();
$tests = array();
$tests['repeated query fields'] = function () {
 $GLOBALS['http_fixture'] = fn()=>response( array() );
 MCP_Gmail_Client::api_request( 'messages', 'GET', array(), array( 'labelIds'=>array( 'INBOX', 'UNREAD' ), 'q'=>'from:person@example.com' ) );
 $url=$GLOBALS['requests'][0]['url'];expect( str_contains($url,'labelIds=INBOX&labelIds=UNREAD') && !str_contains($url,'%5B'), 'Repeated Gmail query fields used PHP array brackets.' );
};
$tests['malformed success response'] = function () {
 $GLOBALS['http_fixture'] = fn()=>array('code'=>200,'body'=>'<html>proxy error</html>');
 expect(is_wp_error(MCP_Gmail_Client::api_request('profile')), 'Invalid JSON was accepted as API success.');
};
$tests['empty successful deletion'] = function () {
 $GLOBALS['http_fixture'] = fn()=>array('code'=>204,'body'=>'');
 expect(array()===MCP_Gmail_Client::api_request('labels/Label_1','DELETE'), 'A valid empty deletion response failed.');
};
$tests['label type filtering'] = function () {
 $GLOBALS['http_fixture'] = fn()=>response(array('labels'=>array(array('id'=>'INBOX','type'=>'system'),array('id'=>'Label_1','type'=>'user'))));
 $result=invoke('gmail/list-labels',array('types'=>array('user')));
 expect(1===$result['count'] && 'Label_1'===$result['labels'][0]['id'], 'Label type filter was not applied.');
};
$tests['label modification arrays'] = function () {
 $GLOBALS['http_fixture'] = fn()=>response(array('labelIds'=>array('UNREAD','STARRED')));
 invoke('gmail/modify',array('message_id'=>'message1','mark_unread'=>true,'add_labels'=>array('UNREAD','STARRED')));
 $body=json_decode($GLOBALS['requests'][0]['args']['body'],true);
 expect(array_keys($body['addLabelIds'])===array(0,1), 'Deduplicated labels were serialized as an object.');
};
$tests['mark-read failure is reported'] = function () {
 $GLOBALS['http_fixture'] = fn($url,$args)=>$args['method']==='GET'?response(array('id'=>'message1','labelIds'=>array('UNREAD'),'payload'=>array())):response(array('error'=>array('message'=>'denied')),403);
 $result=invoke('gmail/get',array('message_id'=>'message1','mark_read'=>true));
 expect(false===$result['success'], 'A failed requested mark-read operation reported success.');
};
$tests['reply recipients and thread references'] = function () {
 $GLOBALS['http_fixture'] = function($url,$args) {
  if ($args['method']==='POST') { return response(array('id'=>'reply1','threadId'=>'thread1')); }
  $headers=array('From'=>'sender@example.com','Reply-To'=>'reply@example.com','To'=>'owner@example.com, other@example.com','Cc'=>'copy@example.com, owner@example.com','Subject'=>'Question','Message-ID'=>'<message@example.com>','References'=>'<earlier@example.com>');
  return response(array('threadId'=>'thread1','payload'=>array('headers'=>array_map(fn($name,$value)=>array('name'=>$name,'value'=>$value),array_keys($headers),array_values($headers)))));
 };
 $result=invoke('gmail/reply',array('message_id'=>'message1','body'=>'<p>Approved fixture reply.</p>','reply_all'=>true));
 expect($result['success'], 'Reply fixture failed.');
 $body=json_decode($GLOBALS['requests'][1]['args']['body'],true);$raw=base64_decode(strtr($body['raw'],'-_','+/'));$head=explode("\r\n\r\n",$raw)[0];
 expect(str_contains($head,'reply@example.com') && str_contains($head,'other@example.com') && str_contains($head,'copy@example.com'), 'Reply-To or original To recipients were omitted.');
 expect(str_contains($head,'<earlier@example.com>') && str_contains($head,'<message@example.com>'), 'Thread reference chain was lost.');
};
$tests['non-ASCII subject and header injection'] = function () {
 $raw=MCP_Gmail_Client::create_message('recipient@example.com','Blåbær og 日本語','<p>Hello</p>','owner@example.com');
 expect(is_string($raw) && str_contains(base64_decode(strtr($raw,'-_','+/')),'=?UTF-8?'), 'Non-ASCII subject was not MIME encoded.');
 expect(is_wp_error(MCP_Gmail_Client::create_message('recipient@example.com',"Subject\r\nBcc: extra@example.com",'<p>Hello</p>','owner@example.com')), 'Header injection was not rejected.');
};
$tests['attachments are not message text'] = function () {
 $part=fn($mime,$name,$body)=>array('mimeType'=>$mime,'filename'=>$name,'body'=>array('data'=>rtrim(strtr(base64_encode($body),'+/','-_'),'=')));
 $body=MCP_Gmail_Client::parse_message_body(array('parts'=>array($part('application/pdf','invoice.pdf','binary attachment'),$part('text/plain','notes.txt','attachment text'),$part('text/plain','','actual message'))));
 expect('actual message'===$body['text'], 'An attachment replaced the message body.');
};
$tests['message identifiers stay in one path segment'] = function () {
 $GLOBALS['http_fixture']=fn()=>response(array('id'=>'fixture','payload'=>array()));
 invoke('gmail/get',array('message_id'=>'a/b?x=1'));
 expect(str_contains($GLOBALS['requests'][0]['url'],'messages/a%2Fb%3Fx%3D1?format=full'),'Message identifier changed request path.');
};
$tests['quoted display name and Bcc MIME'] = function () {
 $raw=MCP_Gmail_Client::create_message('"Smith, Jane" <jane@example.com>, other@example.com','Hello','<p>Hello</p>','owner@example.com',array('Bcc'=>'hidden@example.com'));
 expect(is_string($raw),'Quoted display name rejected.');
 $mime=base64_decode(strtr($raw,'-_','+/'));
 expect(str_contains($mime,'jane@example.com') && str_contains($mime,'other@example.com') && str_contains($mime,'Bcc: hidden@example.com'),'MIME recipients missing.');
};
$tests['invalid credential field types are rejected'] = function () {
 $result=invoke('gmail/configure',array('service_account_json'=>json_encode(array('client_email'=>'service@example.com','private_key'=>array('bad'))),'impersonate_email'=>'owner@example.com'));
 expect(false===$result['success'],'Invalid credential types accepted.');
};
$tests['detail fetch failure is reported'] = function () {
 $GLOBALS['http_fixture']=fn($url)=>str_contains($url,'messages?')?response(array('messages'=>array(array('id'=>'one')))):response(array('error'=>array('message'=>'not found')),404);
 $result=invoke('gmail/list',array('include_details'=>true));
 expect(false===$result['success'],'A failed detail request returned a successful incomplete list.');
};
$failures=0;
foreach($tests as $name=>$test){$requests=array();try{$test();echo "PASS $name\n";}catch(Throwable $e){++$failures;echo "FAIL $name: ".$e->getMessage()."\n";}}
exit($failures?1:0);
