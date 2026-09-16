<?php
// Guvenli ornekler - kurallarin YAKALAMAMASI beklenir

add_action('wp_ajax_myplugin_get', 'myplugin_get');
function myplugin_get() {
    global $wpdb;
    check_ajax_referer('myplugin_nonce', 'nonce');
    if (!current_user_can('manage_options')) { wp_die(); }
    $id = absint($_GET['id']);
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM wp_users WHERE ID = %d", $id));
    echo esc_html($_GET['name']);
}

register_rest_route('myplugin/v1', '/data', array(
    'methods' => 'GET',
    'callback' => 'myplugin_rest',
    'permission_callback' => function () { return current_user_can('edit_posts'); },
));
