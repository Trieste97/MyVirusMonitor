function create_chart(title_, data)  {
	dataPoints = []
	for( var i = 0; i < data['length']; i++ ) {
		dataPoints.push({
			y: data['percs'][i], label: data['av_data'][i][0], av_info:
				"File rilevati: " + data['av_data'][i][1] + "<br>File processati: " +
				data['av_data'][i][2] + "<br>Falsi positivi: " + data['av_data'][i][3]
		});
	}
	var chart = new CanvasJS.Chart("chartContainer",
	{
		title:{ text: "Statistiche Antivirus" },
		axisX: {
			interval: 1
		},
		axisY: {
			title: title_,
			maximum: 100
		},
		data: [
		{
			type: "bar",
			toolTipContent: "<p class=\"text-center\">{y}%<hr/>{av_info}",
			dataPoints: dataPoints
		}]
	});

	chart.render();
}

$("#sort-by-detects").click(function()  {
    $.ajax({
		type: 'GET',
		url: '/sort-antivirus',
		data: {by: "detects"},
        error: function(data) {
			swal({
				title: "C'è stato un errore",
				text: data,
				icon: "error",
			})
		},
		success: function(data) {
            create_chart("Percentuale files rilevati", data);
		},
	});
});

$("#sort-by-processed").click(function()  {
    $.ajax({
		type: 'GET',
		url: '/sort-antivirus',
		data: {by: "processed"},
        error: function(data) {
			swal({
				title: "C'è stato un errore",
				text: data,
				icon: "error",
			})
		},
		success: function(data) {
			create_chart("Percentuale files processati", data);
		},
	});
});

$("#sort-by-false").click(function()  {
    $.ajax({
		type: 'GET',
		url: '/sort-antivirus',
		data: {by: "false"},
        error: function(data) {
			swal({
				title: "C'è stato un errore",
				text: data,
				icon: "error",
			})
		},
		success: function(data) {
			create_chart("Percentuale falsi positivi", data);
		},
	});
});

$("#sort-by-time").click(function()  {
    $.ajax({
		type: 'GET',
		url: '/sort-antivirus',
		data: {by: "time"},
        error: function(data) {
			swal({
				title: "C'è stato un errore",
				text: data,
				icon: "error",
			})
		},
		success: function(data) {

		},
	});
});