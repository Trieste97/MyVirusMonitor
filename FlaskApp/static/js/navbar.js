var navbar = "";
navbar += "<nav class=\"navbar navbar-expand-sm bg-light navbar-light sticky-top d-flex justify-content-center\">";
navbar += "<a href=\"/home\" style=\"margin-right:3%;\"><button type=\"button\" class=\"btn btn-info\">Lista files</button></a>";
navbar += "<a href=\"/av-general-stats\" style=\"margin-right:3%;\"><button type=\"button\" class=\"btn btn-info\">Statistiche AV generali</button></a>";
navbar += "<a href=\"/av-time-stats\" style=\"margin-right:3%;\"><button type=\"button\" class=\"btn btn-info\">Statistiche AV per tempistiche</button></a>";
navbar += "<a href=\"/av-copies-stats\" style=\"margin-right:3%;\"><button type=\"button\" class=\"btn btn-info\">Possibili copie AV</button></a>";
navbar += "</nav>";

$("body").prepend(navbar);