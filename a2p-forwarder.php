<?php

/**
 * Plugin Name:       A2P Forwarder (with Recaptcha Verify)
 * Description:       Verifies reCAPTCHA v3 on the server, then generates X-Signature and forwards to the CRM.
 * Version:           1.1
 * Author:            Your Name
 * License:           GPL-2.0+
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * 1) Replace these with your actual values:
 */
// if (! defined('A2P_HMAC_SECRET')) {
//     define('A2P_HMAC_SECRET', 'g4naN4//moGpv/Gev4JIydVR9TwPnnVyJqkvlFoqdRU=');
// }

if (! defined('A2P_HMAC_SECRET')) {
    define('A2P_HMAC_SECRET', '7hg0HxC1xlDBC46b/SJihXzE697RikDmiYb1Uj++dzk=');
}


if (! defined('A2P_CRM_ENDPOINT')) {
    define('A2P_CRM_ENDPOINT', 'https://digital-services-api-software-qa.montylocal.net/api-gateway/crm-middleware/api/v1/EsimA2P');
}

// Real reCAPTCHA secret key (must match the site key you used on the page, and that key must be allowed for localhost)
if (! defined('A2P_RECAPTCHA_SECRET')) {
    define('A2P_RECAPTCHA_SECRET', '6LdXblYrAAAAACTfSVTL0vWXaH8gAE1M4mvxTeW_');
}

if (! defined('A2P_RECAPTCHA_ENDPOINT')) {
    define('A2P_RECAPTCHA_ENDPOINT', 'https://www.google.com/recaptcha/api/siteverify');
}

/**
 * 2) Hook into admin_post for both logged-in and not-logged-in users.
 */
add_action('admin_post_nopriv_a2p_forward', 'a2p_handle_forward');
add_action('admin_post_a2p_forward',     'a2p_handle_forward');


function a2p_is_rate_limited($ip, $limit = 5, $minutes = 5)
{
    $key = 'a2p_rate_' . md5($ip);
    $requests = get_transient($key);
    $now = time();

    if (!is_array($requests)) {
        $requests = [];
    }

    // Remove timestamps older than $minutes
    $requests = array_filter($requests, function ($timestamp) use ($now, $minutes) {
        return $timestamp > ($now - ($minutes * 60));
    });

    if (count($requests) >= $limit) {
        return true;
    }

    $requests[] = $now;
    set_transient($key, $requests, $minutes * 60);
    return false;
}

/**
 * 3) Handler: verify reCAPTCHA, then forward to CRM.
 */
function a2p_handle_forward()
{

    $ip = $_SERVER['REMOTE_ADDR'];

    if (a2p_is_rate_limited($ip)) {
        return wp_send_json_error('Too many submissions. Please try again later.', 429);
    }

    if (
        ! isset($_POST['forum_form_nonce']) ||
        ! wp_verify_nonce($_POST['forum_form_nonce'], $_POST['unique_action'])
    ) {
        // Invalid request — handle it securely
        return wp_send_json_error("Security check failed. Please try again.");
    }
    // a) Read POST fields from FormData
    $companyName    = isset($_POST['CompanyName'])    ? sanitize_text_field(wp_unslash($_POST['CompanyName']))     : '';
    $fullName      = isset($_POST['FullName'])      ? sanitize_text_field(wp_unslash($_POST['FullName']))       : '';
    $email          = isset($_POST['Email'])          ? sanitize_email(wp_unslash($_POST['Email']))                : '';
    $phone          = isset($_POST['Phone'])          ? sanitize_text_field(wp_unslash($_POST['Phone']))           : '';
    $country        = isset($_POST['Country'])        ? sanitize_text_field(wp_unslash($_POST['Country']))         : '';
    $industry        = isset($_POST['Industry'])        ? sanitize_text_field(wp_unslash($_POST['Industry']))         : '';
    $product        = isset($_POST['Product'])        ? sanitize_text_field(wp_unslash($_POST['Product']))         : '';

    $recaptchaToken = isset($_POST['recaptcha_token']) ? sanitize_text_field(wp_unslash($_POST['recaptcha_token']))  : '';

    $allowed_countries = [
        'AF',
        'AL',
        'DZ',
        'AD',
        'AO',
        'AG',
        'AR',
        'AM',
        'AU',
        'AT',
        'AZ',
        'BS',
        'BH',
        'BD',
        'BB',
        'BY',
        'BE',
        'BZ',
        'BJ',
        'BT',
        'BO',
        'BA',
        'BW',
        'BR',
        'BN',
        'BG',
        'BF',
        'BI',
        'CV',
        'KH',
        'CM',
        'CA',
        'CF',
        'TD',
        'CL',
        'CN',
        'CO',
        'KM',
        'CG',
        'CR',
        'HR',
        'CU',
        'CY',
        'CZ',
        'DK',
        'DJ',
        'DM',
        'DO',
        'EC',
        'EG',
        'SV',
        'GQ',
        'ER',
        'EE',
        'SZ',
        'ET',
        'FJ',
        'FI',
        'FR',
        'GA',
        'GM',
        'GE',
        'DE',
        'GH',
        'GR',
        'GD',
        'GT',
        'GN',
        'GW',
        'GY',
        'HT',
        'VA',
        'HN',
        'HU',
        'IS',
        'IN',
        'ID',
        'IR',
        'IQ',
        'IE',
        'IL',
        'IT',
        'JM',
        'JP',
        'JO',
        'KZ',
        'KE',
        'KI',
        'KP',
        'KR',
        'KW',
        'KG',
        'LA',
        'LV',
        'LB',
        'LS',
        'LR',
        'LY',
        'LI',
        'LT',
        'LU',
        'MG',
        'MW',
        'MY',
        'MV',
        'ML',
        'MT',
        'MH',
        'MR',
        'MU',
        'MX',
        'FM',
        'MD',
        'MC',
        'MN',
        'ME',
        'MA',
        'MZ',
        'MM',
        'NA',
        'NR',
        'NP',
        'NL',
        'NZ',
        'NI',
        'NE',
        'NG',
        'MK',
        'NO',
        'OM',
        'PK',
        'PW',
        'PS',
        'PA',
        'PG',
        'PY',
        'PE',
        'PH',
        'PL',
        'PT',
        'QA',
        'RO',
        'RU',
        'RW',
        'KN',
        'LC',
        'VC',
        'WS',
        'SM',
        'ST',
        'SA',
        'SN',
        'RS',
        'SC',
        'SL',
        'SG',
        'SK',
        'SI',
        'SB',
        'SO',
        'ZA',
        'SS',
        'ES',
        'LK',
        'SD',
        'SR',
        'SE',
        'CH',
        'SY',
        'TJ',
        'TZ',
        'TH',
        'TL',
        'TG',
        'TO',
        'TT',
        'TN',
        'TR',
        'TM',
        'TV',
        'UG',
        'UA',
        'AE',
        'GB',
        'US',
        'UY',
        'UZ',
        'VU',
        'VE',
        'VN',
        'YE',
        'ZM',
        'ZW'
    ];
    // b) Ensure required fields exist
    if ('' === $companyName)     return wp_send_json_error('Missing field: CompanyName');
    if ('' === $fullName)       return wp_send_json_error('Missing field: FullName');
    if ('' === $email)           return wp_send_json_error('Missing field: Email');
    if ('' === $phone)           return wp_send_json_error('Missing field: Phone');
    if ('' === $country)         return wp_send_json_error('Missing field: Country');
    if ('' === $industry)         return wp_send_json_error('Missing field: Industry');
    if ('' === $product)         return wp_send_json_error('Missing field: Product');

    if (! in_array(strtoupper($country), $allowed_countries, true)) {
        return wp_send_json_error('Invalid country selection.');
    }

    if ('' === $recaptchaToken)  return wp_send_json_error('Missing field: recaptcha_token');

    $crm_payload = array(
        'CompanyName' => $companyName,
        'FullName'   => $fullName,
        'Email'       => $email,
        'BusinessPhone'   => $phone,
        'Country'     => $country,
        'Industry'     => $industry,
        'Product'     => $product,
        'Source'      => '6ef80c2f-853f-f011-8779-000d3aaf8826',
        'CampaignId'  => 'b3116cee-88e3-ef11-8eea-6045bd8eaaff'
    );
    $body_json = wp_json_encode($crm_payload, JSON_UNESCAPED_SLASHES);
    // Minify (remove whitespace) to match Postman’s “modifiedBody” logic:
    $minified_body = preg_replace('/\s+/', '', $body_json);

    // e) Compute HMAC-SHA256 signature (binary) and Base64-encode
    $raw_hmac  = hash_hmac('sha256', $minified_body, A2P_HMAC_SECRET, true);
    $signature = base64_encode($raw_hmac);

    // f) Prepare headers for the CRM request
    $headers = array(
        'Accept'         => '*/*',
        'Content-Type'   => 'application/json',
        'X-Signature'    => $signature,
        'RecaptchaToken' => $recaptchaToken,
        'LanguageCode' => 'en',
        'Tenant'       => '4efca093-86e4-416f-98c0-bdf3376061bb',
    );

    // g) Forward to the CRM endpoint
    $crm_response = wp_remote_post(
        A2P_CRM_ENDPOINT,
        array(
            'headers' => $headers,
            'body'    => $body_json,
            'timeout' => 20,
        )
    );

    if (is_wp_error($crm_response)) {
        //return wp_send_json_error('WP_Error forwarding to CRM: ' . $crm_response->get_error_message());
        return wp_send_json_error('An error occured.');
    }

    $status_code   = wp_remote_retrieve_response_code($crm_response);
    $response_body = wp_remote_retrieve_body($crm_response);

    if (200 !== intval($status_code)) {
        //return wp_send_json_error("CRM returned {$status_code}: {$response_body}");
        return wp_send_json_error('An error occured.');
    }

    // h) If we got here, everything succeeded
    return wp_send_json_success('Forwarded successfully.');
}
