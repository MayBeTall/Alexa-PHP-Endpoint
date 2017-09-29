<?php
/**
 * @package Simple
 * Classes intended to make everything simple
 */
namespace MayBeTall\Alexa\Endpoint;

use MayBeTall\Alexa\Endpoint\Request;
use MayBeTall\Alexa\Endpoint\Response;

/**
 * Initializes the libray and handles the Alexa side of the conversation.
 */
class Alexa
{
    /**
     * Init the application.
     */
    public static function init()
    {
        Request::init();
        $attributes = Request::getAttributes();
        Response::init($attributes);
    }

    /**
     * Have Alexa remember something during the conversation.
     * @see Response::addSessionAttribute
     * @param string $key The key used to retrieve the value later.
     * @param mixed $value The value to remember.
     */
    public static function remember($key, $value)
    {
        // Add the value to the response body.
        Response::addSessionAttribute($key, $value);
    }

    /**
     * Get the things Alexa remembers about this conversation.
     * @see Response::getSessionAttribute
     * @param string $attribute The attribute to get.
     * @return mixed The value of the attribute, or null if it didn't exist.
     */
    public static function recall($attribute)
    {
        return Response::getSessionAttribute($attribute);
    }

    /**
     * Get the userid
     * @see Request::getUser
     */
    public static function theUser()
    {
        return Request::getUser();
    }

    /**
     * Make Alexa forget something from the conversation.
     * @see Response::removeSessionAttribute
     * @param string $attribute The attribute to forget, or pass nothing for her to forget everything.
     */
    public static function forget($attribute = null)
    {
        Response::removeSessionAttribute($attribute);
    }

    /**
     * Have Alexa say something.
     * @param string $text The text that Alexa should say. Supports SSML.
     * @param boolean $endSession Defaults to true. If true, ends the skill after speaking.
     */
    public static function say($text, $endSession = true)
    {
        // True if the user passed an SSML formated string.
        // The Alexa documentation always shows SSML wrapped in <speak> so we can use that to tell.
        $ssml = (strpos($text, '<speak>') !== false && strpos($text, '</speak>') !== false);

        // Format the data the way Alexa expects
        $type     = $ssml ? 'SSML' : 'PlainText';
        $property = $ssml ? 'ssml' : 'text';

        // Set up the data
        $say = (object) array(
            "response"         => (object) array(
                "outputSpeech" => (object) array(
                    "type"    => $type,
                    $property => $text,
                ),
            ),
            "shouldEndSession" => $endSession,
        );

        // Append it to the Response and send it to Alexa
        Response::append($say);
        Response::send();
    }

    /**
     * Have Alexa ask something, expecting a reply
     * @param string $text The text that Alexa should say. Supports SSML.
     * @param string $repromt Optional. The text that Alexa should say if the user does not respond. Supports SSML.
     */
    public static function ask($text, $repromt = "")
    {
        $ssml     = (strpos($text, '<speak>') !== false && strpos($text, '</speak>') !== false);
        $type     = $ssml ? 'SSML' : 'PlainText';
        $property = $ssml ? 'ssml' : 'text';

        $ssml2     = (strpos($repromt, '<speak>') !== false && strpos($repromt, '</speak>') !== false);
        $type2     = $ssml2 ? 'SSML' : 'PlainText';
        $property2 = $ssml2 ? 'ssml' : 'text';

        // Set up the data
        $say = (object) array(
            "response" => (object) array(
                "outputSpeech"     => (object) array(
                    "type"    => $type,
                    $property => $text,
                ),
                "reprompt"         => (object) array(
                    "outputSpeech" => (object) array(
                        "type"     => $type2,
                        $property2 => $repromt,
                    ),
                ),
                "shouldEndSession" => false,
            ),
        );

        // Append it to the Response and send it to Alexa
        Response::append($say);
        Response::send();
    }

    /**
     * Runs a function if Alexa skill launched.
     * @param  callable $callback The callback function to run if Alexa just launched
     */
    public static function enters($callback)
    {
        if (Request::getType() == 'LaunchRequest') {
            $callback();
        }
    }

    /**
     * Runs a function if Alexa skill exited.
     * @param  callable $callback The callback function to run if Alexa just exited
     */
    public static function exits($callback)
    {
        if (Request::getType() == 'SessionEndedRequest') {
            $callback();
            // You have to send a responce even if it is empty.
            Response::send();
        }
    }
}
