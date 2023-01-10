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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.TaskSummary = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The TaskSummary model module.
   * @module model/TaskSummary
   */

  /**
   * Constructs a new <code>TaskSummary</code>.
   * @alias module:model/TaskSummary
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>TaskSummary</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/TaskSummary} obj Optional instance to populate.
   * @return {module:model/TaskSummary} The populated <code>TaskSummary</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskId')) {
        obj['taskId'] = ApiClient.convertToType(data['taskId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('requiresApproval')) {
        obj['requiresApproval'] = ApiClient.convertToType(data['requiresApproval'], 'Boolean');
      }
      if (data.hasOwnProperty('dueDateTypeId')) {
        obj['dueDateTypeId'] = ApiClient.convertToType(data['dueDateTypeId'], 'String');
      }
      if (data.hasOwnProperty('dueDateOffset')) {
        obj['dueDateOffset'] = ApiClient.convertToType(data['dueDateOffset'], 'Number');
      }
      if (data.hasOwnProperty('fixedDueDate')) {
        obj['fixedDueDate'] = ApiClient.convertToType(data['fixedDueDate'], 'Date');
      }
      if (data.hasOwnProperty('ownerUserId')) {
        obj['ownerUserId'] = ApiClient.convertToType(data['ownerUserId'], 'Number');
      }
      if (data.hasOwnProperty('completionDate')) {
        obj['completionDate'] = ApiClient.convertToType(data['completionDate'], 'Date');
      }
      if (data.hasOwnProperty('approvalDate')) {
        obj['approvalDate'] = ApiClient.convertToType(data['approvalDate'], 'Date');
      }
      if (data.hasOwnProperty('rejectedDate')) {
        obj['rejectedDate'] = ApiClient.convertToType(data['rejectedDate'], 'Date');
      }
      if (data.hasOwnProperty('createdDate')) {
        obj['createdDate'] = ApiClient.convertToType(data['createdDate'], 'Date');
      }
      if (data.hasOwnProperty('isDocumentTask')) {
        obj['isDocumentTask'] = ApiClient.convertToType(data['isDocumentTask'], 'Boolean');
      }
      if (data.hasOwnProperty('requiresReview')) {
        obj['requiresReview'] = ApiClient.convertToType(data['requiresReview'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {Number} taskId
   */
  exports.prototype['taskId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Boolean} requiresApproval
   */
  exports.prototype['requiresApproval'] = undefined;
  /**
   * @member {String} dueDateTypeId
   */
  exports.prototype['dueDateTypeId'] = undefined;
  /**
   * @member {Number} dueDateOffset
   */
  exports.prototype['dueDateOffset'] = undefined;
  /**
   * @member {Date} fixedDueDate
   */
  exports.prototype['fixedDueDate'] = undefined;
  /**
   * @member {Number} ownerUserId
   */
  exports.prototype['ownerUserId'] = undefined;
  /**
   * @member {Date} completionDate
   */
  exports.prototype['completionDate'] = undefined;
  /**
   * @member {Date} approvalDate
   */
  exports.prototype['approvalDate'] = undefined;
  /**
   * @member {Date} rejectedDate
   */
  exports.prototype['rejectedDate'] = undefined;
  /**
   * @member {Date} createdDate
   */
  exports.prototype['createdDate'] = undefined;
  /**
   * @member {Boolean} isDocumentTask
   */
  exports.prototype['isDocumentTask'] = undefined;
  /**
   * @member {Boolean} requiresReview
   */
  exports.prototype['requiresReview'] = undefined;



  return exports;
}));


