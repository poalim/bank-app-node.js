'use strict';

angular.module('mean.system').controller('IndexController', ['$scope', '$http', '$rootScope', 'Global',
    'Posts', 'SearchPosts', 'MapData', '$location', '$resource', function ($scope, $http, $rootScope, Global, Posts, SearchPosts, MapData, $location, $resource) {
        $scope.global = Global;
        $scope.loginStatus = null;
        $scope.fbPosts = null;
        $scope.fbPlaces = null;
        $scope.postsFromSelectedMarker = null;

        var unbind = $rootScope.$on('golocation', function(event, loc) {
            console.log('event go location:', loc);
            $scope.map.clickedMarker = {
                title: 'found',
                latitude: loc.latitude,
                longitude: loc.longitude
            };

            $scope.gotoLocation(loc.latitude, loc.longitude);
            $scope.addressFromLocation($scope.map.clickedMarker);
        });
        $scope.$on('$destroy', unbind);

        $scope.goMap = function (location) {
            console.log('go location:', location);
            $scope.map.center = location;
            $scope.map.zoom = 16;
        };

        $scope.gotoCurrentLocation = function () {
            if ('geolocation' in navigator) {
                navigator.geolocation.getCurrentPosition(function (position) {
                    var c = position.coords;
                    $scope.gotoLocation(c.latitude, c.longitude);
                });
                return true;
            }
            return false;
        };

        $scope.gotoLocation = function (lat, lon) {

            $scope.map.center.latitude = lat;
            $scope.map.center.longitude = lon;
            $scope.map.zoom = 14;
            $scope.$apply();
        };

        $scope.destinations = [
            { id: 'newyork', verbose: 'New York'},
            { id: 'paris', verbose: 'Paris'},
            { id: 'london', verbose: 'London'},
            { id: 'moscow', verbose: 'Moscow'}
        ];

        $scope.search = '';
        $scope.clickedLocationAsAddress = null;

        $scope.goDestination = function (someDestination) {

            console.log('someDestination:', someDestination);


            $http.get('https://api.bankapp.co.il/account/16998/all', { headers: {
                'SecretKey': 'BWr7nVv44iBLL0TrpVZg4IAbLmzkneD9u3/sytmg', 'AccessKey':'AKIAIENHHDVRGOG4C2XQ'}
            }).success(function(data) {
                    console.log('success', data);
                });


            $scope.search = someDestination.verbose;
            $scope.geoCode();
        };

        $scope.geoCode = function () {
            if ($scope.search && $scope.search.length > 0) {
                if (!this.geocoder) this.geocoder = new google.maps.Geocoder();
                this.geocoder.geocode({ 'address': $scope.search }, function (results, status) {
                    if (status === google.maps.GeocoderStatus.OK) {
                        var loc = results[0].geometry.location;
                        $scope.search = results[0].formatted_address;
                        $scope.gotoLocation(loc.lat(), loc.lng());


                        $scope.map.clickedMarker = {
                            title: 'found',
                            latitude: loc.lat(),
                            longitude: loc.lng()
                        };


                        $scope.addressFromLocation($scope.map.clickedMarker);

                    } else {
                        alert('Sorry, this search produced no results.');
                    }
                });
            }
        };

        $scope.placesById = {};
        $scope.heatmap = null;
        $scope.placesPointArray = [];
        $scope.countPlaces = 0;
        $scope.setHeatLayer = function (someArray) {
            console.log('someArray.length:' + someArray.length);
            for (var i = 0; i < someArray.length; i++) {
                var place = someArray[i];
                if ($scope.placesById[place.id] === undefined) {
                    $scope.placesById[place.id] = place;
                    var point = new google.maps.LatLng(place.location.latitude, place.location.longitude);
                    $scope.placesPointArray.push(point);
                }
            }



            $scope.countPlaces++;
            console.log('size:' + $scope.placesPointArray.length, ' count:', $scope.countPlaces);

            if ($scope.countPlaces < 9) {
                return;
            }
            if ($scope.heatmap !== null) {
                $scope.heatmap.setMap(null);
            }

            var pointArray = new google.maps.MVCArray($scope.placesPointArray);
            $scope.heatmap = new google.maps.visualization.HeatmapLayer({
                data: pointArray
            });

            var map = $scope.map.controls.getGMap();

            $scope.heatmap.setMap(map);
        };


        $scope.addressFromLocation = function (marker) {
            var lat = marker.latitude;
            var lng = marker.longitude;

            if (!this.geocoder) this.geocoder = new google.maps.Geocoder();
            var latlng = new google.maps.LatLng(lat, lng);
            this.geocoder.geocode({'latLng': latlng}, function (results, status) {
                if (status === google.maps.GeocoderStatus.OK) {
                    console.log(results);
                    marker.address = results;
                } else {
                    marker.address = [
                        {address_components: [
                            {short_name: 'unknown'}
                        ]}
                    ];
                }
                marker.title = 'selected';
                $scope.$apply();
            });
        };

        $scope.init = function () {
            if ($scope.global.authenticated) {
                console.log('query FB login status');

                $scope.loginStatus = FB.getLoginStatus(function (response) {
                    if (response.status === 'connected') {
                        console.log('Logged in.', response);
                        //$scope.queryPosts();
                    }
                    else {
                        console.log('call login again??');
                        FB.login(function () {
                            console.log('FB login callback', $scope);
                            //$scope.queryPosts();
                        });
                    }
                });


            } else {
                console.log('not authenticated');
            }
        };

        $scope.onPlaceMarkerClicked = function (marker) {
            console.log(marker);


        };

        $scope.getPlaceFeed = function (place) {
            FB.api('/' + place.id + '/feed', function (response) {
                place.feedResult = response;
                $scope.$apply();
            });

        };

        $scope.queryPlacesByLocation = function(center) {
            FB.api(
                '/search?type=place&' + center + '&distance=1000', function (response) {
                    console.log(response);
                    $scope.fbPlaces = response;

                    $scope.setHeatLayer($scope.fbPlaces.data);
                });
        };

        $scope.queryPlaces = function () {
            $scope.placesById = {};
            $scope.countPlaces = 0;
            $scope.placesPointArray = [];

            var delta = 0.005;
            var center0 = 'center=' + $scope.map.clickedMarker.latitude + ',' + $scope.map.clickedMarker.longitude;
            var center1 = 'center=' + ($scope.map.clickedMarker.latitude + delta) + ',' + ($scope.map.clickedMarker.longitude + delta);
            var center2 = 'center=' + ($scope.map.clickedMarker.latitude - delta) + ',' + ($scope.map.clickedMarker.longitude + delta);
            var center3 = 'center=' + ($scope.map.clickedMarker.latitude + delta) + ',' + ($scope.map.clickedMarker.longitude - delta);
            var center4 = 'center=' + ($scope.map.clickedMarker.latitude - delta) + ',' + ($scope.map.clickedMarker.longitude - delta);

            var center5 = 'center=' + ($scope.map.clickedMarker.latitude) + ',' + ($scope.map.clickedMarker.longitude + delta);
            var center6 = 'center=' + ($scope.map.clickedMarker.latitude) + ',' + ($scope.map.clickedMarker.longitude - delta);
            var center7 = 'center=' + ($scope.map.clickedMarker.latitude + delta) + ',' + ($scope.map.clickedMarker.longitude);
            var center8 = 'center=' + ($scope.map.clickedMarker.latitude - delta) + ',' + ($scope.map.clickedMarker.longitude);

            var points = [center0, center1, center2, center3, center4, center5, center6, center7, center8];
            for (var i = 0; i < points.length; i++) {
                var center = points[i];
                $scope.queryPlacesByLocation(center);
//                FB.api(
//                    '/search?type=place&' + center + '&distance=1000', function (response) {
//                        console.log(response);
//                        $scope.fbPlaces = response;
//
//                        $scope.setHeatLayer($scope.fbPlaces.data);
//                    });
            }
        };

        $scope.queryPosts = function () {
            FB.api(
                '/me/feed', {
                    '*': {
                        'with': 'location'}
                },
                function (response) {
                    if (response && !response.error) {
                        /* handle the result */
                        console.log(response);
                    } else {
                        console.log('error?', response);
                    }
                    $scope.fbPosts = response;

                    $scope.$apply();
                }
            );
        };

        $scope.searchByRectangle = function () {


            var params = {
                bounds: $scope.map.bounds,
                tags: ['food', 'fun']
            };

            SearchPosts.searchWithFilter(params, function (posts) {
                console.log('posts:', posts);

                $scope.posts = posts;
                $scope.map.markers = [];

                for (var i = 0; i < posts.length; i++) {
                    var marker = { showWindow: true, id: i};
                    var post = posts[i];
                    marker.title = post.title;
                    marker.longitude = post.location.coordinates[0];
                    marker.latitude = post.location.coordinates[1];
                    //console.log(marker);
                    $scope.map.markers.push(marker);
                }
            });
        };

        $scope.map = {
            placesMarkers: [],
            clickedMarker: null,
            controls: {},
            events: {
                tilesloaded: function (map, eventName, originalEventArgs) {
                    console.log('tilesloaded,$scope.map.clickedMarker:', $scope.map.clickedMarker);
                    if ($scope.map.clickedMarker === null) {
                        $scope.map.clickedMarker = {
                            title: 'not set'
                        };
                        $scope.map.clickedMarker.longitude = $scope.map.center.longitude;
                        $scope.map.clickedMarker.latitude = $scope.map.center.latitude;
                        $scope.addressFromLocation($scope.map.clickedMarker);

                    }
                },
                zoom_changed: function (map, eventName, originalEventArgs) {
                    console.log('zoom');
                },
                bounds_changed: function (map, eventName, originalEventArgs) {
                    console.log('bounds');
                },
                dragend: function (map, eventName, originalEventArgs) {
                    console.log('dragend', $scope.map.center);

                    $scope.searchByRectangle();
                },
                click: function (mapModel, eventName, originalEventArgs) {
                    // 'this' is the directive's scope
                    console.log('user defined event: ' + eventName, mapModel, originalEventArgs);

                    var e = originalEventArgs[0];

                    if (!$scope.map.clickedMarker) {


                        $scope.map.clickedMarker = {
                            title: 'You clicked here',
                            latitude: e.latLng.lat(),
                            longitude: e.latLng.lng()
                        };
                    }
                    else {
                        var marker = {
                            latitude: e.latLng.lat(),
                            longitude: e.latLng.lng()
                        };

                        var cm = new google.maps.LatLng($scope.map.clickedMarker.latitude, $scope.map.clickedMarker.longitude);
                        var m = new google.maps.LatLng(marker.latitude, marker.longitude);

                        console.log('dist:' + google.maps.geometry.spherical.computeDistanceBetween(cm, m));
                        $scope.map.clickedMarker = marker;
                    }

                    console.log('marker: ', $scope.map.clickedMarker);
                    $scope.addressFromLocation($scope.map.clickedMarker);
                    $scope.queryPlaces();
//                var post = new Posts({
//                    title: 'title',
//                    content: 'wow',
//                    location: {
//                        type: 'Point',
//                        coordinates: [
//                            $scope.map.clickedMarker.longitude,
//                            $scope.map.clickedMarker.latitude]
//                    }
//                });
//
//                console.log('save post:', post);
//                post.$save(function (response) {
//                    console.log(response);
//                    //$location.path('posts/' + response._id);
//                });

                    //scope apply required because this event handler is outside of the angular domain
                    //$scope.$apply();
                }
            },
            center: {latitude: 37.774546,
                longitude: -122.433523 },
//        center: {
//            latitude: 32.07771034554237,
//            longitude: 34.76860736083985 },
            zoom: 13, bounds: {}
        };

        $scope.options = {scrollwheel: false};


        $scope.loadPosts = function () {
            Posts.query(function (posts) {
                //console.log(posts);
                $scope.posts = posts;
                $scope.map.markers = [];

                for (var i = 0; i < posts.length; i++) {
                    var marker = { showWindow: true, id: i};
                    var post = posts[i];
                    marker.title = post.title;
                    marker.longitude = post.location.coordinates[0];
                    marker.latitude = post.location.coordinates[1];
                    //console.log(marker);
                    $scope.map.markers.push(marker);
                }
                //$scope.$apply();
            });
        };

        $scope.onMarkerClicked = function (m) {
            console.log(m);
        };

    }]);