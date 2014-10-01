'use strict';

angular.element(document).ready(function() {
    //Fixing facebook bug with redirect
    if (window.location.hash === '#_=_') window.location.hash = '#!';

    FB.init({
        appId      : window.facebookAppId,
        xfbml      : true,
        version    : 'v2.0'
    });

    //Then init the app
    angular.bootstrap(document, ['mean']);


});

// Dynamically add angular modules declared by packages
var packageModules = [];
for (var index in window.modules) {
    angular.module(window.modules[index].module, window.modules[index].angularDependencies || []);
    packageModules.push(window.modules[index].module);
}

// Default modules
var modules = ['ngCookies', 'ngRoute', 'ngResource', 'ui.bootstrap', 'ui.router', 'google-maps', 'mean.system', 'mean.auth'];
modules = modules.concat(packageModules);

// Combined modules
angular.module('mean', modules);
