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
    define(['ApiClient', 'model/TransactionSide'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TransactionSide'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalTransactionSides = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TransactionSide);
  }
}(this, function(ApiClient, TransactionSide) {
  'use strict';


  /**
   * The GlobalTransactionSides model module.
   * @module model/GlobalTransactionSides
   */

  /**
   * Constructs a new <code>GlobalTransactionSides</code>.
   * @alias module:model/GlobalTransactionSides
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalTransactionSides</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalTransactionSides} obj Optional instance to populate.
   * @return {module:model/GlobalTransactionSides} The populated <code>GlobalTransactionSides</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('transactionSides')) {
        obj['transactionSides'] = ApiClient.convertToType(data['transactionSides'], [TransactionSide]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TransactionSide>} transactionSides
   */
  exports.prototype['transactionSides'] = undefined;



  return exports;
}));


