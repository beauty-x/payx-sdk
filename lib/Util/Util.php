<?php
namespace PayX\Util;

use PayX\PayXObject;
use stdClass;

abstract class Util
{

    /**
     * Whether the provided array (or other) is a list rather than a dictionary.
     *
     * @param array|mixed $array
     * @return boolean True if the given object is a list.
     */
    public static function isList($array)
    {
        if (! is_array($array))
            return false;

            // TODO: generally incorrect, but it's correct given PayX's response
        foreach (array_keys($array) as $k) {
            if (! is_numeric($k))
                return false;
        }
        return true;
    }

    /**
     * Recursively converts the PHP PayX object to an array.
     *
     * @param array $values
     *            The PHP PayX object to convert.
     * @param
     *            bool
     * @return array
     */
    public static function convertPayXObjectToArray($values, $keep_object = false)
    {
        $results = array();
        foreach ($values as $k => $v) {
            // FIXME: this is an encapsulation violation
            if ($k[0] == '_') {
                continue;
            }
            if ($v instanceof PayXObject) {
                $results[$k] = $keep_object ? $v->__toStdObject(true) : $v->__toArray(true);
            } else
                if (is_array($v)) {
                    $results[$k] = self::convertPayXObjectToArray($v, $keep_object);
                } else {
                    $results[$k] = $v;
                }
        }
        return $results;
    }

    /**
     * Recursively converts the PHP PayX object to an stdObject.
     *
     * @param array $values
     *            The PHP PayX object to convert.
     * @return array
     */
    public static function convertPayXObjectToStdObject($values)
    {
        $results = new stdClass();
        foreach ($values as $k => $v) {
            // FIXME: this is an encapsulation violation
            if ($k[0] == '_') {
                continue;
            }
            if ($v instanceof PayXObject) {
                $results->$k = $v->__toStdObject(true);
            } else
                if (is_array($v)) {
                    $results->$k = self::convertPayXObjectToArray($v, true);
                } else {
                    $results->$k = $v;
                }
        }
        return $results;
    }

    /**
     * Converts a response from the PayX API to the corresponding PHP object.
     *
     * @param stdObject $resp
     *            The response from the PayX API.
     * @param array $opts
     * @return PayXObject|array
     */
    public static function convertToPayXObject($resp, $opts)
    {
        $types = array(
            'red_envelope' => 'PayX\\RedEnvelope',
            'charge' => 'PayX\\Charge',
            'list' => 'PayX\\Collection',
            'refund' => 'PayX\\Refund',
            'event' => 'PayX\\Event',
            'transfer' => 'PayX\\Transfer',
            'customer' => 'PayX\\Customer',
            'card' => 'PayX\\Card',
            'sms_code' => 'PayX\\SmsCode',
            'card_info' => 'PayX\\CardInfo',
            'token' => 'PayX\\Token'
        );
        if (self::isList($resp)) {
            $mapped = array();
            foreach ($resp as $i)
                array_push($mapped, self::convertToPayXObject($i, $opts));
            return $mapped;
        } elseif (is_object($resp)) {
            if (isset($resp->object) && is_string($resp->object) && isset($types[$resp->object])) {
                $class = $types[$resp->object];
            } else {
                $class = 'PayX\\PayXObject';
            }
            return $class::constructFrom($resp, $opts);
        } else {
            return $resp;
        }
    }

    public static function getRequestHeaders()
    {
        if (function_exists('getallheaders')) {
            $headers = array();
            foreach (getallheaders() as $name => $value) {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('-', ' ', $name))))] = $value;
            }
            return $headers;
        }
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }

    /**
     *
     * @param string|mixed $value
     *            A string to UTF8-encode.
     *
     * @return s string|mixed The UTF8-encoded string, or the object passed in if
     *         it wasn't a string.
     */
    public static function utf8($value)
    {
        if (is_string($value) && mb_detect_encoding($value, "UTF-8", TRUE) != "UTF-8") {
            return utf8_encode($value);
        } else {
            return $value;
        }
    }
}
