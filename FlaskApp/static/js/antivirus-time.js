function create_chart(order, data)  {
	//SORTING
	function sortFunction(a, b){
		value1 = data['av_data'][a]['avg_days'];
		value2 = data['av_data'][b]['avg_days'];
        
		return ((value1 > value2) ? -1 : ((value1 > value2) ? 1 : 0));
	}

	sorted_av_list = []
	for(av_name in data['av_data'])  {
		sorted_av_list.push(av_name);
	}
	sorted_av_list.sort(sortFunction);

	dataPoints = []
	for(i in sorted_av_list) {
		var av_name = sorted_av_list[i];
		var avg_days = data['av_data'][av_name]['avg_days'];
		var num_files = data['av_data'][av_name]['files'];

		dataPoints.push({
			y: avg_days,
			label: av_name,
			av_info: "Media su " + num_files + " files"
		});
	}

	var chart = new CanvasJS.Chart("chartContainer",
	{
		title:{ text: "Statistiche AV" },
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
			}
		]
	});

	chart.render();
}