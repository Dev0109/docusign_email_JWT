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
    root.DocusignRooms.UserToInvite = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.AccessLevel);
  }
}(this, function(ApiClient, AccessLevel) {
  'use strict';


  /**
   * The UserToInvite model module.
   * @module model/UserToInvite
   */

  /**
   * Constructs a new <code>UserToInvite</code>.
   * @alias module:model/UserToInvite
   * @class
   * @param firstName {String} 
   * @param lastName {String} 
   * @param email {String} 
   * @param roleId {Number} 
   * @param accessLevel {module:model/AccessLevel} 
   * @param defaultOfficeId {Number} 
   * @param eSignPermissionProfileId {String} 
   */
  var exports = function(firstName, lastName, email, roleId, accessLevel, defaultOfficeId, eSignPermissionProfileId) {
    var _this = this;

    _this['firstName'] = firstName;    _this['lastName'] = lastName;    _this['email'] = email;    _this['roleId'] = roleId;    _this['accessLevel'] = accessLevel;    _this['defaultOfficeId'] = defaultOfficeId;    _this['eSignPermissionProfileId'] = eSignPermissionProfileId;
  };

  /**
   * Constructs a <code>UserToInvite</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserToInvite} obj Optional instance to populate.
   * @return {module:model/UserToInvite} The populated <code>UserToInvite</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('firstName')) {
        obj['firstName'] = ApiClient.convertToType(data['firstName'], 'String');
      }
      if (data.hasOwnProperty('lastName')) {
        obj['lastName'] = ApiClient.convertToType(data['lastName'], 'String');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('roleId')) {
        obj['roleId'] = ApiClient.convertToType(data['roleId'], 'Number');
      }
      if (data.hasOwnProperty('accessLevel')) {
        obj['accessLevel'] = AccessLevel.constructFromObject(data['accessLevel']);
      }
      if (data.hasOwnProperty('defaultOfficeId')) {
        obj['defaultOfficeId'] = ApiClient.convertToType(data['defaultOfficeId'], 'Number');
      }
      if (data.hasOwnProperty('regions')) {
        obj['regions'] = ApiClient.convertToType(data['regions'], ['Number']);
      }
      if (data.hasOwnProperty('offices')) {
        obj['offices'] = ApiClient.convertToType(data['offices'], ['Number']);
      }
      if (data.hasOwnProperty('eSignPermissionProfileId')) {
        obj['eSignPermissionProfileId'] = ApiClient.convertToType(data['eSignPermissionProfileId'], 'String');
      }
      if (data.hasOwnProperty('redirectUrl')) {
        obj['redirectUrl'] = ApiClient.convertToType(data['redirectUrl'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} firstName
   */
  exports.prototype['firstName'] = undefined;
  /**
   * @member {String} lastName
   */
  exports.prototype['lastName'] = undefined;
  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {Number} roleId
   */
  exports.prototype['roleId'] = undefined;
  /**
   * @member {module:model/AccessLevel} accessLevel
   */
  exports.prototype['accessLevel'] = undefined;
  /**
   * @member {Number} defaultOfficeId
   */
  exports.prototype['defaultOfficeId'] = undefined;
  /**
   * @member {Array.<Number>} regions
   */
  exports.prototype['regions'] = undefined;
  /**
   * @member {Array.<Number>} offices
   */
  exports.prototype['offices'] = undefined;
  /**
   * @member {String} eSignPermissionProfileId
   */
  exports.prototype['eSignPermissionProfileId'] = undefined;
  /**
   * @member {String} redirectUrl
   */
  exports.prototype['redirectUrl'] = undefined;



  return exports;
}));


