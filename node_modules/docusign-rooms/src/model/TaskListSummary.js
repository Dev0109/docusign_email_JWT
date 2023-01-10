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
    root.DocusignRooms.TaskListSummary = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The TaskListSummary model module.
   * @module model/TaskListSummary
   */

  /**
   * Constructs a new <code>TaskListSummary</code>.
   * @alias module:model/TaskListSummary
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>TaskListSummary</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/TaskListSummary} obj Optional instance to populate.
   * @return {module:model/TaskListSummary} The populated <code>TaskListSummary</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskListId')) {
        obj['taskListId'] = ApiClient.convertToType(data['taskListId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('taskListTemplateId')) {
        obj['taskListTemplateId'] = ApiClient.convertToType(data['taskListTemplateId'], 'Number');
      }
      if (data.hasOwnProperty('submittedForReviewDate')) {
        obj['submittedForReviewDate'] = ApiClient.convertToType(data['submittedForReviewDate'], 'Date');
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
      if (data.hasOwnProperty('approvedByUserId')) {
        obj['approvedByUserId'] = ApiClient.convertToType(data['approvedByUserId'], 'Number');
      }
      if (data.hasOwnProperty('rejectedByUserId')) {
        obj['rejectedByUserId'] = ApiClient.convertToType(data['rejectedByUserId'], 'Number');
      }
      if (data.hasOwnProperty('comment')) {
        obj['comment'] = ApiClient.convertToType(data['comment'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {Number} taskListId
   */
  exports.prototype['taskListId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} taskListTemplateId
   */
  exports.prototype['taskListTemplateId'] = undefined;
  /**
   * @member {Date} submittedForReviewDate
   */
  exports.prototype['submittedForReviewDate'] = undefined;
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
   * @member {Number} approvedByUserId
   */
  exports.prototype['approvedByUserId'] = undefined;
  /**
   * @member {Number} rejectedByUserId
   */
  exports.prototype['rejectedByUserId'] = undefined;
  /**
   * @member {String} comment
   */
  exports.prototype['comment'] = undefined;



  return exports;
}));


