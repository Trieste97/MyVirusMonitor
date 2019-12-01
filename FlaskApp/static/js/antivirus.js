function create_chart(order, data)  {
	//SORTING
	function sortByDetects(a, b){
		var value1 = 0, value2 = 0;
		if(order == "detects")  {
			value1 = data['av_stats'][a]['perc_detected'];
			value2 = data['av_stats'][b]['perc_detected'];
		} else if(order == "false")  {
			value1 = data['av_stats'][a]['perc_false'];
			value2 = data['av_stats'][b]['perc_false'];
		} else  {
			value1 = data['av_stats'][a]['perc_processed'];
			value2 = data['av_stats'][b]['perc_processed'];
		}
		return ((value1 < value2) ? -1 : ((value1 > value2) ? 1 : 0));
	}

	sorted_av_list = []
	for(av_name in data['av_stats'])  {
		sorted_av_list.push(av_name);
	}
	sorted_av_list.sort(sortByDetects);

	detects_dataPoints = []
	false_dataPoints = []
	processed_dataPoints = []
	for(i in sorted_av_list) {
		var av_name = sorted_av_list[i];
		var num_detected = data['av_stats'][av_name]['files_detected'];
		var num_processed = data['av_stats'][av_name]['files_processed'];
		var num_falses = data['av_stats'][av_name]['false_positives'];
		var perc_detected = data['av_stats'][av_name]['perc_detected'];
		var perc_false = data['av_stats'][av_name]['perc_false'];
		var perc_processed = data['av_stats'][av_name]['perc_processed'];

		detects_dataPoints.push({
			y: perc_detected,
			label: av_name,
			click: function(e){
				create_chart("detects", data);
			},
			av_info:
				"File rilevati: " + num_detected + 
				"<br>File processati: " + num_processed
		});

		false_dataPoints.push({
			y: perc_false,
			label: av_name,
			click: function(e){
				create_chart("false", data);
			},
			av_info:
				"Falsi positivi: " + num_falses + 
				"<br>File processati: " + num_processed
		});

		processed_dataPoints.push({
			y: perc_processed,
			label: av_name,
			click: function(e){
				create_chart("processed", data);
			},
			av_info:
				"File processati: " + num_processed + 
				"<br>File totali: " + data['num_files']
		});
	}

	var chart = new CanvasJS.Chart("chartContainer",
	{
		title:{ text: "Statistiche AV" },
		axisX: {
			interval: 1
		},
		axisY: {
			title: "Statistiche AV",
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

			chart.options.data.forEach(function(element) {
				element.dataPoints.sort(compareDataPointYDescend);
			});
			chart.render();
		},
	});
});

function compareDataPointYDescend(dataPoint1, dataPoint2) {
	return dataPoint1.y - dataPoint2.y;
}