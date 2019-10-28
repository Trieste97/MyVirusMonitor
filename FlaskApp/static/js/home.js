function get_file_info(id_)  {
	window.location.replace("file?id=" + id_);
}

$('#upload-file-btn').click(function() {
	var form_data = new FormData($('#upload-file')[0]);

	$.ajax({
		type: 'POST',
		url: '/add',
		data: form_data,
		contentType: false,
		cache: false,
		processData: false,
		success: function(data) {
			if(data == "success")  {
				swal({
					title: "File caricato",
					text: "Potrebbe volerci un po' prima di vederlo in lista",
					icon: "success",
				})
			}
			else if(data == "too_many_files")  {
				swal({
					title: "File non caricato",
					text: "Troppi files in attesa di scan, provare più tardi",
					icon: "error",
				})
			}
			else if(data == "too_big")  {
				swal({
					title: "File non caricato",
					text: "File troppo grande, dimensione max: 100MB",
					icon: "error",
				})
			}
			else if(data == "too_many_files_db")  {
				swal({
					title: "File non caricato",
					text: "Troppi files monitorati, cancellarne qualcuno",
					icon: "error",
				})
			}
			else if(data == "not_supported_format")  {
				swal({
					title: "File non caricato",
					text: "Formato file non supportato",
					icon: "error",
				})
			}
		},
		error: function(data) {
			swal({
				title: "C'è stato un errore",
				text: "Il file non è stato caricato, riprova",
				icon: "error",
			})
		},
	});
});

function remove_file(id_)  {
	swal({
		title: "Sicuro?",
		icon: "warning",
		buttons: true,
		dangerMode: true,
	}).then((willDelete) => {
		if (willDelete) {

			$.ajax({
				url: "rmv",
				type: "POST",
				data: {id: id_ }
			}).done(function(data) {
				if(data == "success")  {
					$('#file_' + id_).remove();
					swal("File cancellato dal sistema", {
						icon: "success",
					});
				}
				else if(data == "error")  {
					swal("C'è stato qualche errore cancellando il file", {
						icon: "error",
					});
				}
			})
		}
	});
	event.stopPropagation();
}