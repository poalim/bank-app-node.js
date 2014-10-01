/**
 * Created by Leonid on 03/08/14.
 */
'use strict';

//Global service for global variables
angular.module('mean.system').factory('MapUtils', [

    function() {
        var _this = this;

        /**
         * add address data from google on given marker
         * @param marker
         * @param cb
         */
        _this.putAddressOnMarker = function(marker, cb) {
            var lat = marker.latitude;
            var lng = marker.longitude;

            if (!_this.geocoder) _this.geocoder = new google.maps.Geocoder();
            var latlng = new google.maps.LatLng(lat, lng);
            _this.geocoder.geocode({'latLng': latlng}, function (results, status) {
                if (status === google.maps.GeocoderStatus.OK) {
                    //console.log(results);
                    marker.address = results;
                } else {
                    marker.address = [
                        {address_components: [
                            {short_name: 'unknown'}
                        ]}
                    ];
                }


            });


        };

        _this.getBoundsFromNative = function(map) {
            var bounds = map.getBounds();
            var ne = bounds.getNorthEast(); // LatLng
            var sw = bounds.getSouthWest(); // LatLng

            var res = { northeast : {}, southwest : {}};
            res.northeast.latitude = ne.lat();
            res.northeast.longitude = ne.lng();
            res.southwest.latitude = sw.lat();
            res.southwest.longitude = sw.lng();
            return res;
        };
        return _this;
    }]);
