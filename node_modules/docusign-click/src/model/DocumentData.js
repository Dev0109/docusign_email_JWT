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
    root.DocusignClick.DocumentData = factory(root.DocusignClick.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DocumentData model module.
   * @module model/DocumentData
   */

  /**
   * Constructs a new <code>DocumentData</code>.
   * The object of data to be merged with the clickwrap document. A merged document must be created from Click's web editor and supports fullName, email, company, title and date.
   * @alias module:model/DocumentData
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DocumentData</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DocumentData} obj Optional instance to populate.
   * @return {module:model/DocumentData} The populated <code>DocumentData</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('fullName')) {
        obj['fullName'] = ApiClient.convertToType(data['fullName'], 'String');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('company')) {
        obj['company'] = ApiClient.convertToType(data['company'], 'String');
      }
      if (data.hasOwnProperty('jobTitle')) {
        obj['jobTitle'] = ApiClient.convertToType(data['jobTitle'], 'String');
      }
      if (data.hasOwnProperty('date')) {
        obj['date'] = ApiClient.convertToType(data['date'], 'String');
      }
    }
    return obj;
  }

  /**
   * The full name of the signer. This field is created in the UI editor for a Clickwrap document. Only required if present in the document.
   * @member {String} fullName
   */
  exports.prototype['fullName'] = undefined;
  /**
   * The email address of the signer. This field is created in the UI editor for a Clickwrap document. Only required if present in the document.
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * The company name of the signer. This field is created in the UI editor for a Clickwrap document. Only required if present in the document.
   * @member {String} company
   */
  exports.prototype['company'] = undefined;
  /**
   * The job title of the signer. This field is created in the UI editor for a Clickwrap document. Only required if present in the document.
   * @member {String} jobTitle
   */
  exports.prototype['jobTitle'] = undefined;
  /**
   * A custom date for the contract. This field is created in the UI editor for a Clickwrap document. Only required if present in the document.
   * @member {String} date
   */
  exports.prototype['date'] = undefined;



  return exports;
}));


