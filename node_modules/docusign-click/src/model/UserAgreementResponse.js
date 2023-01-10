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
    define(['ApiClient', 'model/DisplaySettings', 'model/Document'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DisplaySettings'), require('./Document'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignClick) {
      root.DocusignClick = {};
    }
    root.DocusignClick.UserAgreementResponse = factory(root.DocusignClick.ApiClient, root.DocusignClick.DisplaySettings, root.DocusignClick.Document);
  }
}(this, function(ApiClient, DisplaySettings, Document) {
  'use strict';


  /**
   * The UserAgreementResponse model module.
   * @module model/UserAgreementResponse
   */

  /**
   * Constructs a new <code>UserAgreementResponse</code>.
   * @alias module:model/UserAgreementResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UserAgreementResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserAgreementResponse} obj Optional instance to populate.
   * @return {module:model/UserAgreementResponse} The populated <code>UserAgreementResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('accountId')) {
        obj['accountId'] = ApiClient.convertToType(data['accountId'], 'String');
      }
      if (data.hasOwnProperty('agreedOn')) {
        obj['agreedOn'] = ApiClient.convertToType(data['agreedOn'], Object);
      }
      if (data.hasOwnProperty('agreementId')) {
        obj['agreementId'] = ApiClient.convertToType(data['agreementId'], 'String');
      }
      if (data.hasOwnProperty('agreementUrl')) {
        obj['agreementUrl'] = ApiClient.convertToType(data['agreementUrl'], 'String');
      }
      if (data.hasOwnProperty('clickwrapId')) {
        obj['clickwrapId'] = ApiClient.convertToType(data['clickwrapId'], 'String');
      }
      if (data.hasOwnProperty('clientUserId')) {
        obj['clientUserId'] = ApiClient.convertToType(data['clientUserId'], 'String');
      }
      if (data.hasOwnProperty('consumerDisclosureEnabled')) {
        obj['consumerDisclosureEnabled'] = ApiClient.convertToType(data['consumerDisclosureEnabled'], 'Boolean');
      }
      if (data.hasOwnProperty('consumerDisclosureHtml')) {
        obj['consumerDisclosureHtml'] = ApiClient.convertToType(data['consumerDisclosureHtml'], 'String');
      }
      if (data.hasOwnProperty('createdOn')) {
        obj['createdOn'] = ApiClient.convertToType(data['createdOn'], Object);
      }
      if (data.hasOwnProperty('declinedOn')) {
        obj['declinedOn'] = ApiClient.convertToType(data['declinedOn'], Object);
      }
      if (data.hasOwnProperty('documentData')) {
        obj['documentData'] = ApiClient.convertToType(data['documentData'], {'String': 'String'});
      }
      if (data.hasOwnProperty('documents')) {
        obj['documents'] = ApiClient.convertToType(data['documents'], [Document]);
      }
      if (data.hasOwnProperty('metadata')) {
        obj['metadata'] = ApiClient.convertToType(data['metadata'], 'String');
      }
      if (data.hasOwnProperty('settings')) {
        obj['settings'] = DisplaySettings.constructFromObject(data['settings']);
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('style')) {
        obj['style'] = ApiClient.convertToType(data['style'], {'String': 'String'});
      }
      if (data.hasOwnProperty('version')) {
        obj['version'] = ApiClient.convertToType(data['version'], 'String');
      }
      if (data.hasOwnProperty('versionId')) {
        obj['versionId'] = ApiClient.convertToType(data['versionId'], 'String');
      }
      if (data.hasOwnProperty('versionNumber')) {
        obj['versionNumber'] = ApiClient.convertToType(data['versionNumber'], 'Number');
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} accountId
   */
  exports.prototype['accountId'] = undefined;
  /**
   * 
   * @member {Object} agreedOn
   */
  exports.prototype['agreedOn'] = undefined;
  /**
   * 
   * @member {String} agreementId
   */
  exports.prototype['agreementId'] = undefined;
  /**
   * 
   * @member {String} agreementUrl
   */
  exports.prototype['agreementUrl'] = undefined;
  /**
   * 
   * @member {String} clickwrapId
   */
  exports.prototype['clickwrapId'] = undefined;
  /**
   * 
   * @member {String} clientUserId
   */
  exports.prototype['clientUserId'] = undefined;
  /**
   * 
   * @member {Boolean} consumerDisclosureEnabled
   */
  exports.prototype['consumerDisclosureEnabled'] = undefined;
  /**
   * 
   * @member {String} consumerDisclosureHtml
   */
  exports.prototype['consumerDisclosureHtml'] = undefined;
  /**
   * 
   * @member {Object} createdOn
   */
  exports.prototype['createdOn'] = undefined;
  /**
   * 
   * @member {Object} declinedOn
   */
  exports.prototype['declinedOn'] = undefined;
  /**
   * 
   * @member {Object.<String, String>} documentData
   */
  exports.prototype['documentData'] = undefined;
  /**
   * 
   * @member {Array.<module:model/Document>} documents
   */
  exports.prototype['documents'] = undefined;
  /**
   * 
   * @member {String} metadata
   */
  exports.prototype['metadata'] = undefined;
  /**
   * @member {module:model/DisplaySettings} settings
   */
  exports.prototype['settings'] = undefined;
  /**
   * 
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * 
   * @member {Object.<String, String>} style
   */
  exports.prototype['style'] = undefined;
  /**
   * 
   * @member {String} version
   */
  exports.prototype['version'] = undefined;
  /**
   * 
   * @member {String} versionId
   */
  exports.prototype['versionId'] = undefined;
  /**
   * 
   * @member {Number} versionNumber
   */
  exports.prototype['versionNumber'] = undefined;



  return exports;
}));


