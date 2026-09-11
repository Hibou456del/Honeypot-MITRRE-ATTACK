<?php
// Fake configuration file for honeypot
// This is a decoy file - all credentials are fictional

$db_host = 'localhost';
$db_user = 'fake_admin_user';
$db_pass = 'fake_password_123456';
$db_name = 'fake_production_database';

$api_key = 'fake_api_key_xyz123abc789';
$secret_key = 'fake_secret_key_def456ghi012';

$backup_enabled = true;
$backup_path = '/var/backups/fake_database.sql';
$backup_schedule = '0 2 * * *';

$admin_email = 'fake_admin@example.com';
$admin_password = 'fake_admin_pass_789';

// Security settings (all fake)
$encryption_key = 'fake_encryption_key_abcdefghijklmnop';
$jwt_secret = 'fake_jwt_secretqrstuvwxyz123456';

error_reporting(E_ALL);
log_errors = true;
error_log = '/var/log/php_errors.log';
?>