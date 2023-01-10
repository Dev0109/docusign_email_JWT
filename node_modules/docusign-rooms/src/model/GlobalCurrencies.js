/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/Currency'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./Currency'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalCurrencies = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.Currency);
  }
}(this, function(ApiClient, Currency) {
  'use strict';


  /**
   * The GlobalCurrencies model module.
   * @module model/GlobalCurrencies
   */

  /**
   * Constructs a new <code>GlobalCurrencies</code>.
   * @alias module:model/GlobalCurrencies
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalCurrencies</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalCurrencies} obj Optional instance to populate.
   * @return {module:model/GlobalCurrencies} The populated <code>GlobalCurrencies</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('currencies')) {
        obj['currencies'] = ApiClient.convertToType(data['currencies'], [Currency]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/Currency>} currencies
   */
  exports.prototype['currencies'] = undefined;



  return exports;
}));


