function create_chart(title_, data)  {
	detects_dataPoints = []
	false_dataPoints = []
	processed_dataPoints = []
	for(av_name in data['av_stats']) {
		var num_detected = data['av_stats'][av_name]['files_detected'];
		var num_processed = data['av_stats'][av_name]['files_processed'];
		var num_falses = data['av_stats'][av_name]['false_positives'];
		var perc_detected = data['av_stats'][av_name]['perc_detected'];
		var perc_false = data['av_stats'][av_name]['perc_false'];
		var perc_processed = data['av_stats'][av_name]['perc_processed'];

		detects_dataPoints.push({
			y: perc_detected,
			label: av_name,
			av_info:
				"File rilevati: " + num_detected + 
				"<br>File processati: " + num_processed
		});

		false_dataPoints.push({
			y: perc_false,
			label: av_name,
			av_info:
				"Falsi positivi: " + num_falses + 
				"<br>File processati: " + num_processed
		});

		processed_dataPoints.push({
			y: perc_processed,
			label: av_name,
			av_info:
				"File processati: " + num_processed + 
				"<br>File totali: " + data['num_files']
		});
	}

	var chart = new CanvasJS.Chart("chartContainer",
	{
		title:{ text: title_ },
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
				dataPoints: detects_dataPoints
			},
			{
				type: "bar",
				toolTipContent: "<p class=\"text-center\">{y}%<hr/>{av_info}",
				dataPoints: false_dataPoints
			},
			{
				type: "bar",
				toolTipContent: "<p class=\"text-center\">{y}%<hr/>{av_info}",
				dataPoints: processed_dataPoints
			}
		]
	});

	chart.render();
}

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