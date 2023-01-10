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
    define(['ApiClient', 'model/DomainResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DomainResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.DomainsResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DomainResponse);
  }
}(this, function(ApiClient, DomainResponse) {
  'use strict';


  /**
   * The DomainsResponse model module.
   * @module model/DomainsResponse
   */

  /**
   * Constructs a new <code>DomainsResponse</code>.
   * @alias module:model/DomainsResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DomainsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DomainsResponse} obj Optional instance to populate.
   * @return {module:model/DomainsResponse} The populated <code>DomainsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('reserved_domains')) {
        obj['reserved_domains'] = ApiClient.convertToType(data['reserved_domains'], [DomainResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/DomainResponse>} reserved_domains
   */
  exports.prototype['reserved_domains'] = undefined;



  return exports;
}));


