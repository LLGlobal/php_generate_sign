<?php

namespace pay;

class Lianlianpayment
{
    // send box
    public $LL_API_URL = 'https://test-global-api.lianlianpay-inc.com';
    public $LL_PUBLIC_KEY = '';
    public $LL_DEVELOPER_ID = '';
    public $LL_ACCESS_TOKEN = '';
    public $LL_PRIVATE_KEY = '';

    private $authorization = '';

    public function __construct()
    {
        $this->authorization = "Basic " . base64_encode($this->LL_DEVELOPER_ID . ':' . $this->LL_ACCESS_TOKEN);
    }

    public function payout($order)
    {
        $payload = [
            'request_id' => strval($order['number']),
            'business_order_id' => strval($order['number']),
            'account_id' => strval($order['number']),
            'pay_currency' => 'USD',
            'pay_amount' => '12.26',
            'purpose' => 'purpose'
        ];

        $URI = '/gateway/v1/ew-payouts';
        $requestUrl = $this->LL_API_URL . $URI;
        $header = $this->makeHeaderStr(time(), $URI, json_encode($payload), '', 'POST');
        $res = $this->curl($requestUrl, json_encode($payload), true, $header);
        return json_decode($res, 1);
    }

    public function balances()
    {

        $URI = '/gateway/v1/ew-balances';
        $requestUrl = $this->LL_API_URL . $URI;
        $header = $this->makeHeaderStr(time(), $URI, '');
        $res = $this->curl($requestUrl, '', false, $header);
        return json_decode($res, 1);
    }

    private function makeHeaderStr($t, $URI, $PAYLOAD_json = '', $QUERY_STRING_urlencode = '', $method = 'GET')
    {
        $v = $this->makeSignatureValue($t, $URI, $PAYLOAD_json, $QUERY_STRING_urlencode, $method);
        $header = [
            'Content-Type: application/json',
            'Authorization:' . $this->authorization,
            'LLPAY-Signature:t=' . $t . ',v=' . $v
        ];
        return $header;
    }

    private function makeSignatureValue($t, $URI, $PAYLOAD_json = '', $QUERY_STRING_urlencode = '', $method = 'GET')
    {
        if ($PAYLOAD_json && $QUERY_STRING_urlencode) {
            $v = $method . '&' . $URI . '&' . $t . '&' . $PAYLOAD_json . '&' . $QUERY_STRING_urlencode;
        } elseif ($PAYLOAD_json && !$QUERY_STRING_urlencode) {
            $v = $method . '&' . $URI . '&' . $t . '&' . $PAYLOAD_json;
        } elseif (!$PAYLOAD_json && $QUERY_STRING_urlencode) {
            $v = $method . '&' . $URI . '&' . $t . '&&' . $QUERY_STRING_urlencode;
        } else {
            $v = $method . '&' . $URI . '&' . $t . '&';
        }
        $signature = '';
        openssl_sign($v, $signature, $this->priKey($this->LL_PRIVATE_KEY), OPENSSL_ALGO_SHA256);
        $v = base64_encode($signature);
        return $v;
    }

    public function checkSign($signature, $payload)
    {
        $temp = explode(',', $signature);
        $t = str_replace('t=', '', $temp[0]);
        $v = substr($temp[1], 2);
        $str = $t . '&' . $payload;
        $res = $this->verify_sign($str, $v, ($this->LL_PUBLIC_KEY));
        return $res;
    }

    public function verify_sign($data, $sign, $pubKey)
    {
        $sign = base64_decode($sign);

        $pubKey = "-----BEGIN PUBLIC KEY-----\n" .
            wordwrap($pubKey, 64, "\n", true) .
            "\n-----END PUBLIC KEY-----";

        $key = openssl_pkey_get_public($pubKey);
        $result = openssl_verify($data, $sign, $key, OPENSSL_ALGO_SHA256) === 1;
        return $result;
    }

    private function priKey($privateKey)
    {
        $privateKey = chunk_split($privateKey, 64, "\n");

        $privateKey = "-----BEGIN RSA PRIVATE KEY-----\n$privateKey-----END RSA PRIVATE KEY-----\n";

        return $privateKey;
    }

    public function pubKey($pubKey)
    {
        $fKey = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($pubKey, 64, "\n") . '-----END PUBLIC KEY-----';
        return $fKey;
    }


    private function curl($url, $data = [], $isPost = false, $header = [])
    {

        $curl = curl_init();

        if ($isPost) {
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        } else {
            if ($data) {
                $data = http_build_query($data);
                if (strpos($url, '?') !== false) {
                    $url = $url . '&' . $data;
                } else {
                    $url = $url . '?' . $data;
                }
            }
        }

        if ($header) {
            curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        }

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, 0);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);

        $response = curl_exec($curl);
        $result = $this->xml_parser($response) ? $this->xmlToArray($response) : $response;
        $error = curl_error($curl);

        curl_close($curl);

        return $error ? $error : $result;
    }

    public function xmlToArray($xml)
    {
        libxml_disable_entity_loader(true);
        $arr = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $arr;
    }

    private function xml_parser($str)
    {
        $xml_parser = xml_parser_create();
        if (!xml_parse($xml_parser, $str, true)) {
            xml_parser_free($xml_parser);
            return false;
        } else {
            return (json_decode(json_encode(simplexml_load_string($str)), true));
        }
    }
}
