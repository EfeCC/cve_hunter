<?php
// Zafiyetli ornekler - kurallarin YAKALAMASI beklenir

add_action('wp_ajax_nopriv_myplugin_get', 'myplugin_get');
function myplugin_get() {
    global $wpdb;
    // SQLi: prepare yok
    $id = $_GET['id'];
    $row = $wpdb->get_row("SELECT * FROM wp_users WHERE ID = $id");
    // Reflected XSS: escape yok
    echo $_GET['name'];
    // LFI: kullanici girdisi include'a
    include($_GET['tpl'] . '.php');
    // Object injection
    $obj = unserialize($_POST['data']);
}

register_rest_route('myplugin/v1', '/data', array(
    'methods' => 'GET',
    'callback' => 'myplugin_rest',
));

register_rest_route('myplugin/v1', '/open', array(
    'methods' => 'POST',
    'callback' => 'myplugin_open',
    'permission_callback' => '__return_true',
));
