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
    define(['ApiClient', 'model/AccessLevel'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./AccessLevel'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.UserSummary = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.AccessLevel);
  }
}(this, function(ApiClient, AccessLevel) {
  'use strict';


  /**
   * The UserSummary model module.
   * @module model/UserSummary
   */

  /**
   * Constructs a new <code>UserSummary</code>.
   * @alias module:model/UserSummary
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>UserSummary</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserSummary} obj Optional instance to populate.
   * @return {module:model/UserSummary} The populated <code>UserSummary</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('userId')) {
        obj['userId'] = ApiClient.convertToType(data['userId'], 'Number');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('firstName')) {
        obj['firstName'] = ApiClient.convertToType(data['firstName'], 'String');
      }
      if (data.hasOwnProperty('lastName')) {
        obj['lastName'] = ApiClient.convertToType(data['lastName'], 'String');
      }
      if (data.hasOwnProperty('isLockedOut')) {
        obj['isLockedOut'] = ApiClient.convertToType(data['isLockedOut'], 'Boolean');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('accessLevel')) {
        obj['accessLevel'] = AccessLevel.constructFromObject(data['accessLevel']);
      }
      if (data.hasOwnProperty('defaultOfficeId')) {
        obj['defaultOfficeId'] = ApiClient.convertToType(data['defaultOfficeId'], 'Number');
      }
      if (data.hasOwnProperty('titleId')) {
        obj['titleId'] = ApiClient.convertToType(data['titleId'], 'Number');
      }
      if (data.hasOwnProperty('roleId')) {
        obj['roleId'] = ApiClient.convertToType(data['roleId'], 'Number');
      }
      if (data.hasOwnProperty('profileImageUrl')) {
        obj['profileImageUrl'] = ApiClient.convertToType(data['profileImageUrl'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {Number} userId
   */
  exports.prototype['userId'] = undefined;
  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {String} firstName
   */
  exports.prototype['firstName'] = undefined;
  /**
   * @member {String} lastName
   */
  exports.prototype['lastName'] = undefined;
  /**
   * @member {Boolean} isLockedOut
   */
  exports.prototype['isLockedOut'] = undefined;
  /**
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {module:model/AccessLevel} accessLevel
   */
  exports.prototype['accessLevel'] = undefined;
  /**
   * @member {Number} defaultOfficeId
   */
  exports.prototype['defaultOfficeId'] = undefined;
  /**
   * @member {Number} titleId
   */
  exports.prototype['titleId'] = undefined;
  /**
   * @member {Number} roleId
   */
  exports.prototype['roleId'] = undefined;
  /**
   * @member {String} profileImageUrl
   */
  exports.prototype['profileImageUrl'] = undefined;



  return exports;
}));


