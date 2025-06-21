<?php

/*
 +-----------------------------------------------------------------------+
 | Roundcube Webmail Configuration for Elemta MTA
 +-----------------------------------------------------------------------+
 */

// Database configuration
$config['db_dsnw'] = 'sqlite:////var/roundcube/db/sqlite.db?mode=0646';

// IMAP Configuration - Connect to Dovecot
$config['default_host'] = 'elemta-dovecot';
$config['default_port'] = 14143;
$config['imap_timeout'] = 120;
$config['imap_auth_type'] = 'PLAIN';
$config['imap_delimiter'] = null;
$config['imap_ns_personal'] = null;
$config['imap_ns_other'] = null;
$config['imap_ns_shared'] = null;
$config['imap_force_caps'] = false;
$config['imap_force_lsub'] = false;
$config['imap_force_ns'] = false;
$config['imap_conn_options'] = null;

// SMTP Configuration - Connect to Elemta MTA
$config['smtp_server'] = 'elemta';
$config['smtp_port'] = 2525;
$config['smtp_user'] = '';
$config['smtp_pass'] = '';
$config['smtp_auth_type'] = null;
$config['smtp_timeout'] = 120;
$config['smtp_conn_options'] = null;

// Interface Configuration
$config['support_url'] = '';
$config['product_name'] = 'Elemta Webmail';
$config['des_key'] = 'elemta_webmail_secure_key_2025';
$config['plugins'] = array(
    'archive',
    'zipdownload',
    'markasjunk',
    'managesieve',
    'password'
);

// Security Settings
$config['session_lifetime'] = 30; // 30 minutes
$config['ip_check'] = true;
$config['referer_check'] = true;
$config['x_frame_options'] = 'deny';

// User Interface
$config['skin'] = 'elastic';
$config['language'] = 'en_US';
$config['timezone'] = 'UTC';
$config['date_format'] = 'Y-m-d';
$config['time_format'] = 'H:i';

// Message Composition
$config['draft_autosave'] = 60;
$config['max_message_size'] = '1M';
$config['mdn_requests'] = 0;

// Address Book Configuration (LDAP Integration)
$config['ldap_public'] = array(
    'elemta_ldap' => array(
        'name'          => 'Elemta Directory',
        'hosts'         => array('elemta-ldap'),
        'port'          => 389,
        'use_tls'       => false,
        'ldap_version'  => '3',
        'network_timeout' => 10,
        'user_specific' => false,
        'base_dn'       => 'ou=people,dc=example,dc=com',
        'bind_dn'       => 'cn=admin,dc=example,dc=com',
        'bind_pass'     => 'admin',
        'search_fields' => array('mail', 'cn', 'uid'),
        'fieldmap' => array(
            'name'        => 'cn',
            'surname'     => 'sn',
            'firstname'   => 'givenName',
            'email'       => 'mail:*',
            'phone:home'  => 'homePhone',
            'phone:work'  => 'telephoneNumber',
            'phone:mobile' => 'mobile',
            'department'  => 'departmentNumber',
            'jobtitle'    => 'title',
            'organization' => 'o',
        ),
        'sort'          => 'cn',
        'scope'         => 'sub',
        'filter'        => '(objectClass=posixAccount)',
        'fuzzy_search'  => true,
        'vlv'           => false,
        'sizelimit'     => 0,
        'timelimit'     => 0,
        'referrals'     => false,
    ),
);

// Logging
$config['log_driver'] = 'stdout';
$config['log_level'] = 4;
$config['per_user_logging'] = false;

// Disable installer
$config['enable_installer'] = false;

// Additional security
$config['force_https'] = false; // Set to true in production
$config['login_autocomplete'] = 2;
$config['password_charset'] = 'UTF-8';

// Performance
$config['enable_caching'] = true;
$config['messages_cache'] = 'db';
$config['imap_cache'] = 'db';

// Managesieve (Sieve filters) - for Dovecot integration
$config['managesieve_port'] = 4190;
$config['managesieve_host'] = 'elemta-dovecot';
$config['managesieve_auth_type'] = null;
$config['managesieve_auth_cid'] = null;
$config['managesieve_auth_pw'] = null;
$config['managesieve_usetls'] = false;

// Password plugin configuration for LDAP
$config['password_driver'] = 'ldap';
$config['password_ldap_host'] = 'elemta-ldap';
$config['password_ldap_port'] = 389;
$config['password_ldap_starttls'] = false;
$config['password_ldap_version'] = 3;
$config['password_ldap_basedn'] = 'ou=people,dc=example,dc=com';
$config['password_ldap_method'] = 'user';
$config['password_ldap_adminDN'] = 'cn=admin,dc=example,dc=com';
$config['password_ldap_adminPW'] = 'admin';
$config['password_ldap_search_base'] = 'ou=people,dc=example,dc=com';
$config['password_ldap_search_filter'] = '(mail=%login)';
$config['password_ldap_passwdattr'] = 'userPassword';
$config['password_ldap_force_replace'] = true;
$config['password_ldap_lchattr'] = '';
$config['password_ldap_samba'] = false;

?> 