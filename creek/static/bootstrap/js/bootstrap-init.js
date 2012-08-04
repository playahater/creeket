$(document).ready(function () {

  $('.dropdown-toggle').dropdown()
  $(".alert").alert()

  $('a#run').bind('click', function() {
    $("#result").text('Loading ..');
    $.getJSON($SCRIPT_ROOT + '/_execute', {
      /*url: document.URL*/
      url: document.URL.split('/').slice(-1)[0]
    }, function(data) {
      $("#result").text(data.data);
    });
    return false;
  });

});
