'use strict';

angular.module('mean.system').controller('HeaderController', ['$scope', '$rootScope', 'Global', 'Menus',
    function($scope, $rootScope, Global, Menus) {
        $scope.global = Global;
        $scope.menus = {};

        $scope.init = function() {
            console.log('header init');

            $scope.loginStatus = FB.getLoginStatus(function (response) {
                if (response.status === 'connected') {
                    console.log('header, Logged in.', response);
                    Global.fb.loginStatus = response;

                    $rootScope.$emit('fbLogin');
                    FB.api('/me/picture?width=70&height=70',  function(response) {
                        console.log('profile:', response.data.url);
                        Global.fb.profilePictureUrl = response.data.url;
                    });

                    FB.api('/me', function(response) {
                        console.log('Good to see you, ' + response.name + '.');
                        Global.fb.meResponse = response;
                    });
                }
                else {
                    console.log('you should perform login to facebook');
//                    FB.login(function (response) {
//                        console.log('FB login callback');
//                        if (response.authResponse) {
//                            console.log('Welcome!  Fetching your information.... ');
//                            FB.api('/me', function(response) {
//                                console.log('Good to see you, ' + response.name + '.');
//                                Global.fb.meResponse = response;
//                            });
//                        } else {
//                            console.log('User cancelled login or did not fully authorize.');
//                        }
//                    });
                }
            });
        };

        $scope.gotoCurrentLocation = function () {
            if ('geolocation' in navigator) {
                navigator.geolocation.getCurrentPosition(function (position) {
                    var c = position.coords;

                    //$scope.gotoLocation(c.latitude, c.longitude);
                    $rootScope.$emit('golocation', c);
                });
                return true;
            }
            return false;
        };

        $scope.geoCode = function () {
            if ($scope.search && $scope.search.length > 0) {
                if (!this.geocoder) this.geocoder = new google.maps.Geocoder();
                this.geocoder.geocode({ 'address': $scope.search }, function (results, status) {
                    if (status === google.maps.GeocoderStatus.OK) {
                        var loc = results[0].geometry.location;
                        $scope.search = results[0].formatted_address;
                        console.log(' $scope.search:'+ $scope.search);
                        //$scope.gotoLocation(loc.lat(), loc.lng());
                        var location = { latitude : loc.lat(), longitude : loc.lng() };
                        $rootScope.$emit('golocation', location);
                        $scope.$apply();
                    } else {
                        alert('Sorry, this search produced no results.');
                    }
                });
            }
        };

        // Default hard coded menu items for main menu
        var defaultMainMenu = [];

        // Query menus added by modules. Only returns menus that user is allowed to see.
        function queryMenu(name, defaultMenu) {

            Menus.query({
                name: name,
                defaultMenu: defaultMenu
            }, function(menu) {
                $scope.menus[name] = menu;
            });
        }

        // Query server for menus and check permissions
        queryMenu('main', defaultMainMenu);

        $scope.isCollapsed = false;

        $rootScope.$on('loggedin', function() {
            console.log('header on loggedin');
            queryMenu('main', defaultMainMenu);

            $scope.global = {
                authenticated: !! $rootScope.user,
                user: $rootScope.user
            };


        });

    }
]);
