function create_chart(title_, data)  {
	dataPoints = []
	for( var i = 0; i < data['length']; i++ ) {
		dataPoints.push({
			y: data['percs'][i],
			label: data['av_data'][i][0],
			av_info:
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
			interval: 10,
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
			dataPoints = []
			for( var item in data ) {
				dataPoints.push({
					y: data[item][2],
					label: item,
					av_info:
						"Numero files rilevati dopo la prima volta (di altri AV): " + data[item][1]
				});
			}

			var chart = new CanvasJS.Chart("chartContainer",
			{
				title:{ text: "Statistiche Antivirus" },
				axisX: {
					interval: 1
				},
				axisY: {
					title: "Giorni medi attesi prima della rilevazione",
					interval: 20
				},
				data: [
				{
					type: "bar",
					toolTipContent: "<p class=\"text-center\">{y} giorni<hr/>{av_info}",
					dataPoints: dataPoints
				}]
			});

			chart.options.data[0].dataPoints.sort(compareDataPointYDescend);
			chart.render();
		},
	});
});

function compareDataPointYDescend(dataPoint1, dataPoint2) {
	return dataPoint2.y - dataPoint1.y;
}