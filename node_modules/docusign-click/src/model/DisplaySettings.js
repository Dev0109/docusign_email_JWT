/**
 * DocuSign Click API
 * DocuSign Click lets you capture consent to standard agreement terms with a single click: terms and conditions, terms of service, terms of use, privacy policies, and more. The Click API lets you include this customizable clickwrap solution in your DocuSign integrations.
 *
 * OpenAPI spec version: v1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.DisplaySettings = factory(root.DocusignClick.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DisplaySettings model module.
   * @module model/DisplaySettings
   */

  /**
   * Constructs a new <code>DisplaySettings</code>.
   * @alias module:model/DisplaySettings
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DisplaySettings</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DisplaySettings} obj Optional instance to populate.
   * @return {module:model/DisplaySettings} The populated <code>DisplaySettings</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('actionButtonAlignment')) {
        obj['actionButtonAlignment'] = ApiClient.convertToType(data['actionButtonAlignment'], 'String');
      }
      if (data.hasOwnProperty('allowClientOnly')) {
        obj['allowClientOnly'] = ApiClient.convertToType(data['allowClientOnly'], 'Boolean');
      }
      if (data.hasOwnProperty('allowedHosts')) {
        obj['allowedHosts'] = ApiClient.convertToType(data['allowedHosts'], ['String']);
      }
      if (data.hasOwnProperty('brandId')) {
        obj['brandId'] = ApiClient.convertToType(data['brandId'], 'String');
      }
      if (data.hasOwnProperty('consentButtonText')) {
        obj['consentButtonText'] = ApiClient.convertToType(data['consentButtonText'], 'String');
      }
      if (data.hasOwnProperty('consentText')) {
        obj['consentText'] = ApiClient.convertToType(data['consentText'], 'String');
      }
      if (data.hasOwnProperty('declineButtonText')) {
        obj['declineButtonText'] = ApiClient.convertToType(data['declineButtonText'], 'String');
      }
      if (data.hasOwnProperty('displayName')) {
        obj['displayName'] = ApiClient.convertToType(data['displayName'], 'String');
      }
      if (data.hasOwnProperty('documentDisplay')) {
        obj['documentDisplay'] = ApiClient.convertToType(data['documentDisplay'], 'String');
      }
      if (data.hasOwnProperty('downloadable')) {
        obj['downloadable'] = ApiClient.convertToType(data['downloadable'], 'Boolean');
      }
      if (data.hasOwnProperty('format')) {
        obj['format'] = ApiClient.convertToType(data['format'], 'String');
      }
      if (data.hasOwnProperty('hasDeclineButton')) {
        obj['hasDeclineButton'] = ApiClient.convertToType(data['hasDeclineButton'], 'Boolean');
      }
      if (data.hasOwnProperty('mustRead')) {
        obj['mustRead'] = ApiClient.convertToType(data['mustRead'], 'Boolean');
      }
      if (data.hasOwnProperty('mustView')) {
        obj['mustView'] = ApiClient.convertToType(data['mustView'], 'Boolean');
      }
      if (data.hasOwnProperty('recordDeclineResponses')) {
        obj['recordDeclineResponses'] = ApiClient.convertToType(data['recordDeclineResponses'], 'Boolean');
      }
      if (data.hasOwnProperty('requireAccept')) {
        obj['requireAccept'] = ApiClient.convertToType(data['requireAccept'], 'Boolean');
      }
      if (data.hasOwnProperty('sendToEmail')) {
        obj['sendToEmail'] = ApiClient.convertToType(data['sendToEmail'], 'Boolean');
      }
      if (data.hasOwnProperty('statementAlignment')) {
        obj['statementAlignment'] = ApiClient.convertToType(data['statementAlignment'], 'String');
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} actionButtonAlignment
   */
  exports.prototype['actionButtonAlignment'] = undefined;
  /**
   * 
   * @member {Boolean} allowClientOnly
   */
  exports.prototype['allowClientOnly'] = undefined;
  /**
   * 
   * @member {Array.<String>} allowedHosts
   */
  exports.prototype['allowedHosts'] = undefined;
  /**
   * 
   * @member {String} brandId
   */
  exports.prototype['brandId'] = undefined;
  /**
   * 
   * @member {String} consentButtonText
   */
  exports.prototype['consentButtonText'] = undefined;
  /**
   * 
   * @member {String} consentText
   */
  exports.prototype['consentText'] = undefined;
  /**
   * 
   * @member {String} declineButtonText
   */
  exports.prototype['declineButtonText'] = undefined;
  /**
   * 
   * @member {String} displayName
   */
  exports.prototype['displayName'] = undefined;
  /**
   * 
   * @member {String} documentDisplay
   */
  exports.prototype['documentDisplay'] = undefined;
  /**
   * 
   * @member {Boolean} downloadable
   */
  exports.prototype['downloadable'] = undefined;
  /**
   * 
   * @member {String} format
   */
  exports.prototype['format'] = undefined;
  /**
   * 
   * @member {Boolean} hasDeclineButton
   */
  exports.prototype['hasDeclineButton'] = undefined;
  /**
   * 
   * @member {Boolean} mustRead
   */
  exports.prototype['mustRead'] = undefined;
  /**
   * 
   * @member {Boolean} mustView
   */
  exports.prototype['mustView'] = undefined;
  /**
   * 
   * @member {Boolean} recordDeclineResponses
   */
  exports.prototype['recordDeclineResponses'] = undefined;
  /**
   * 
   * @member {Boolean} requireAccept
   */
  exports.prototype['requireAccept'] = undefined;
  /**
   * 
   * @member {Boolean} sendToEmail
   */
  exports.prototype['sendToEmail'] = undefined;
  /**
   * 
   * @member {String} statementAlignment
   */
  exports.prototype['statementAlignment'] = undefined;



  return exports;
}));


