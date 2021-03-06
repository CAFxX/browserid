/*jshint browser:true, jQuery: true, forin: true, laxbreak:true */                                             
/*globals BrowserID: true, _:true */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla bid.
 *
 * The Initial Developer of the Original Code is Mozilla.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
steal.plugins("jquery", "funcunit/qunit").then("/dialog/resources/tooltip", function() {
  "use strict";

  var bid = BrowserID,
      tooltip = bid.Tooltip

  module("/resources/tooltip", {
    setup: function() {
    },
    teardown: function() {
    }
  });


  test("show short tooltip, min of 2.5 seconds", function() {
    var startTime = new Date().getTime();

    tooltip.showTooltip("#shortTooltip", function() {
      var endTime = new Date().getTime();
      var diff = endTime - startTime;
      ok(2000 <= diff && diff <= 3000, diff + " - minimum of 2 seconds, max of 3 seconds");

      start();
    });

    var el = $("#createdTooltip");
    equal(el.length, 1, "one tooltip created");
    var contents = el.html() || "";
    equal(contents.indexOf("contents") === -1, true, "contents have been replaced");

    stop();
  });

  test("show long tooltip, takes about 5 seconds", function() {
    var startTime = new Date().getTime();

    tooltip.showTooltip("#longTooltip", function() {
      var endTime = new Date().getTime();
      var diff = endTime - startTime;
      ok(diff >= 4500, diff + " - longer tooltip is on the screen for a bit longer");

      start();
    });

    stop();
  });

});
