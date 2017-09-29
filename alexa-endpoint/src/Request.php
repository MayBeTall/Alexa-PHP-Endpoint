<?php
/**
 * @package Advanced
 * If you want more control, look through these classes.
 */
namespace MayBeTall\Alexa\Endpoint;

use MayBeTall\Alexa\Endpoint\Intent;

/**
 * Handles the requests sent by the Alexa Skill.
 * @link https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/docs/alexa-skills-kit-interface-reference#request-format Alexa's Request Format
 */
class Request
{
    /**
     * The payload sent by the Alexa Skill.
     * @var object
     */
    private static $payload;

    /**
     * The type of request.
     * @link https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/docs/custom-standard-request-types-reference Alexa's Request Types
     * @var string
     */
    private static $type;

    /**
     * Parses the request sent by the Alexa Skill.
     */
    public static function init()
    {
        // Get the payload from the request
        self::$payload = json_decode(file_get_contents('php://input'));

        // Validate request, kill if not valid
        $valid = self::isValid();
        if (!$valid) {
            error_log('Application not authorized.');
            die('Application not authorized.');
        }

        // Set request type
        self::$type = self::$payload->request->type;

        // Handle IntentRequest
        if (self::$type == 'IntentRequest') {
            Intent::init(self::$payload->request->intent);
        }
    }

    /**
     * Gets the payload object
     * @return string The payload object sent by Alexa.
     */
    public static function getPayload()
    {
        return self::$payload;
    }

    /**
     * Gets the attributes object
     * @return string The attributes sent by Alexa.
     */
    public static function getAttributes()
    {
        if (property_exists(self::$payload->session, 'attributes')) {
            return self::$payload->session->attributes;
        } else {
            return (object) array();
        }

    }

    public static function getUser()
    {
        if (property_exists(self::$payload->session, 'user')) {
            return self::$payload->session->user->userId;
        } else {
            return "na";
        }
    }

    /**
     * Gets the request type.
     * @return string The request type.
     */
    public static function getType()
    {
        return self::$type;
    }

    /**
     * Checks if the request is valid and sent by supported application ids.
     * @return boolean Whether the request should be accepted or not.
     */
    protected static function isValid()
    {
        // If there is no payload return false
        if (!self::$payload) {
            return false;
        }

        $applicationId = self::$payload->session->application->applicationId;
        $validId       = in_array($applicationId, SUPPORTED_APPLICATION_IDS);

        // If the ID is a valid ID or the app is allowing all IDs.
        if ($validId || ALLOW_ALL_REQUESTS) {
            return true;
        } else {
            return false;
        }
    }
}
