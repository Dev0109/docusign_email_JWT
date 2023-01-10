/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/LinkResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./LinkResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.CertificateResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.LinkResponse);
  }
}(this, function(ApiClient, LinkResponse) {
  'use strict';


  /**
   * The CertificateResponse model module.
   * @module model/CertificateResponse
   */

  /**
   * Constructs a new <code>CertificateResponse</code>.
   * @alias module:model/CertificateResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>CertificateResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/CertificateResponse} obj Optional instance to populate.
   * @return {module:model/CertificateResponse} The populated <code>CertificateResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('issuer')) {
        obj['issuer'] = ApiClient.convertToType(data['issuer'], 'String');
      }
      if (data.hasOwnProperty('thumbprint')) {
        obj['thumbprint'] = ApiClient.convertToType(data['thumbprint'], 'String');
      }
      if (data.hasOwnProperty('expiration_date')) {
        obj['expiration_date'] = ApiClient.convertToType(data['expiration_date'], 'Date');
      }
      if (data.hasOwnProperty('is_valid')) {
        obj['is_valid'] = ApiClient.convertToType(data['is_valid'], 'Boolean');
      }
      if (data.hasOwnProperty('links')) {
        obj['links'] = ApiClient.convertToType(data['links'], [LinkResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} issuer
   */
  exports.prototype['issuer'] = undefined;
  /**
   * @member {String} thumbprint
   */
  exports.prototype['thumbprint'] = undefined;
  /**
   * @member {Date} expiration_date
   */
  exports.prototype['expiration_date'] = undefined;
  /**
   * @member {Boolean} is_valid
   */
  exports.prototype['is_valid'] = undefined;
  /**
   * @member {Array.<module:model/LinkResponse>} links
   */
  exports.prototype['links'] = undefined;



  return exports;
}));


