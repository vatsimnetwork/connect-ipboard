<?php

namespace IPS\Login;

class _VATSIMSSOv2 extends LoginAbstract

{

    /**
     * @brief    Icon
     */

    public static $icon = 'lock';

    /**
     * Get Form
     *
     * @param  \IPS\Http\Url  $url  The URL for the login page
     * @param  bool  $ucp  If this is being done from the User CP
     *
     * @return    string
     */

    public function loginForm($url, $ucp = false)
    {

        $redirectUrl = \IPS\Http\Url::internal("login/?loginProcess=VATSIMSSOv2", "none");

        return "<a href='$redirectUrl' type='submit' class='ipsButton ipsButton_primary'>VATSIM LOGIN</a>";

    }

    /**
     * Authenticate
     *
     * @param  string  $url  The URL for the login page
     * @param  \IPS\Member  $member  If we want to integrate this login method with an existing member, provide the
     *                               member object
     *
     * @return    \IPS\Member
     * @throws    \IPS\Login\Exception
     */

    public function authenticate($url, $member = null)
    {

        if ($member !== null) {

            return $member;

        }

        try {
            $returnUrl = $this->settings['base_url'].'/index.php?login&loginProcess=VATSIMSSOv2&remember_me=1&return=true';

            /* Determine if the user has come back from VATSIM */
            if (isset(\IPS\Request::i()->code)) {
                /* Send the user to VATSIM to authorize */
                try {
                    $url = "https://auth.vatsim.net/oauth/token";
                    $fields = array(
                        'client_id' => urlencode($this->settings['client_id']),
                        'client_secret' => urlencode($this->settings['client_secret']),
                        'grant_type' => urlencode('authorization_code'),
                        'redirect_uri' => urlencode($returnUrl),
                        'code' => urlencode(\IPS\Request::i()->code),
                    );
                    foreach ($fields as $key => $value) {
                        $fields_string .= $key.'='.$value.'&';
                    }
                    rtrim($fields_string, '&');
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_POST, count($fields));
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    $result = curl_exec($ch);
                    $data = json_decode($result);
                    curl_close($ch);
                } catch (\IPS\Http\Request\Exception $e) {
                    /* Catch Exception */
                    throw new \IPS\Login\Exception('generic_error', \IPS\Login\Exception::INTERNAL_ERROR);
                }

                try {
                    /* Use the Authorization_code to get an Access_token */
                    $ch = curl_init('https://auth.vatsim.net/api/user');
                    $authorization = "Authorization: Bearer ".$data->access_token;
                    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json', $authorization));
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
                    $result = curl_exec($ch);
                    $result = json_decode($result);
                    curl_close($ch);
                } catch (\IPS\Http\Request\Exception $e) {
                    /* Catch Exception */
                    throw new \IPS\Login\Exception('generic_error', \IPS\Login\Exception::INTERNAL_ERROR);
                }

                /* Verify that the required information has been returned from VATSIM */
                if (!isset($result->data->personal->email) || !isset($result->data->personal->name_first) || !isset($result->data->personal->name_last)) {
                    header("Location: ".$this->settings['sso_requirements_url']);
                    exit;
                }

                if ($result && isset($result->data->cid)) {

                    /* Search for a member by their VATSIM ID */

                    $member = \IPS\Login\VatsimMember::load($result->data->cid, 'vatsim_cid');

                    /* If no member is returned, create one */
                    if (!$member->member_id) {

                        $member = new \IPS\Login\VatsimMember;
                        $member->member_group_id = \IPS\Settings::i()->member_group;

                    }

                    /* Take the returned user or created user and update their details */
                    $member->vatsim_cid = $result->data->cid;
                    $member->name = $result->data->personal->name_first." ".$result->data->personal->name_last;
                    $member->email = isset($result->data->personal->email) ? $result->data->personal->email : null;
                    $member->save();

                    return $member;

                }
            } else {
                /* Send the user to VATSIM to authorize */
                $query = http_build_query([
                    'client_id' => $this->settings['client_id'],
                    'redirect_uri' => $returnUrl,
                    'response_type' => 'code',
                    'scope' => $this->settings['scope'],
                ]);

                header("Location: https://auth.vatsim.net/oauth/authorize?".$query);
            }

            /* Catch Exception */
            throw new \IPS\Login\Exception('generic_error', \IPS\Login\Exception::INTERNAL_ERROR);

        } catch (\IPS\Http\Request\Exception $e) {

            throw new \IPS\Login\Exception('generic_error', \IPS\Login\Exception::INTERNAL_ERROR);

        }

    }

    /**
     * Link Account
     *
     * @param  \IPS\Member  $member  The member
     * @param  mixed  $details  Details as they were passed to the exception thrown in authenticate()
     *
     * @return    void
     */

    public static function link(\IPS\Member $member, $details)
    {

        return;

    }

    /**
     * ACP Settings Form
     *
     * @param  string  $url  URL to redirect user to after successful submission
     *
     * @return    array    List of settings to save - settings will be stored to core_login_handlers.login_settings DB
     *                     field
     * @code
     *
     * return array( 'savekey'    => new \IPS\Helpers\Form\[Type]( ... ), ... );
     * @endcode
     */

    public function acpForm()

    {

        \IPS\Output::i()->sidebar['actions'] = array(

            'help' => array(

                'title' => 'help',

                'icon' => 'question-circle',

                'link' => \IPS\Http\Url::external('https://auth.vatsim.net'),

                'target' => '_blank',

                'class' => ''

            ),

        );

        return array(

            'base_url' => new \IPS\Helpers\Form\Text('login_vatsim_base_url',
                (isset($this->settings['base_url'])) ? $this->settings['base_url'] : '', true),

            'client_id' => new \IPS\Helpers\Form\Text('login_vatsim_client_id',
                (isset($this->settings['client_id'])) ? $this->settings['client_id'] : '', true),

            'client_secret' => new \IPS\Helpers\Form\Password('login_vatsim_client_secret',
                (isset($this->settings['client_secret'])) ? $this->settings['client_secret'] : '', true),

            'sso_requirements_url' => new \IPS\Helpers\Form\Text('login_vatsim_sso_requirements_url',
                (isset($this->settings['sso_requirements_url'])) ? $this->settings['sso_requirements_url'] : '', true),

            'scope' => new \IPS\Helpers\Form\TextArea('login_vatsim_scope',
                (isset($this->settings['scope'])) ? $this->settings['scope'] : '', true)

        );

    }

    /**
     * Can a member change their email/password with this login handler?
     *
     * @param  string  $type  'email' or 'password'
     * @param  \IPS\Member  $member  The member
     *
     * @return    bool
     */

    public function canChange($type, \IPS\Member $member)
    {

        return false;

    }

    public function canProcess(\IPS\Member $member)
    {

        return false;

    }

}
